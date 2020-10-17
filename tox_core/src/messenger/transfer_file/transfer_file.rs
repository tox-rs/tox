use std::ops::{Add, Sub};
use std::collections::HashMap;
use std::sync::Arc;

use tox_binary_io::*;
use tox_crypto::*;
// use crate::time::*;
use tokio::sync::RwLock;
use futures::{future, Future, TryFutureExt};
use futures::future::Either;
use bitflags::*;

use tox_packet::messenger::FileTransferPacket;
use tox_packet::messenger::{FileUID, FileControl, TransferDirection, ControlType, FileData};
use crate::friend_connection::FriendConnections;
use crate::net_crypto::NetCrypto;
use futures::channel::mpsc::{UnboundedSender, Sender};
use tox_packet::dht::MAX_CRYPTO_DATA_SIZE;
use crate::messenger::transfer_file::errors::*;

/// Because `file_id` is `u8` this const can not be larger than 256.
pub const MAX_CONCURRENT_FILE_PIPES: u32 = 256;

/// File transferring status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransferStatus {
    /// Not accepted
    NotAccepted,
    /// Transferring
    Transferring,
    /// Finished
    Finished,
}

bitflags! {
    /// File transferring pause status
    pub struct PauseStatus: u8 {
        /// Not paused
        const FT_NONE = 0;
        /// Paused by us
        const US = 1;
        /// Paused by other
        const OTHER = 2;
        /// Paused by both
        const BOTH = 3;
    }
}

/** Struct holds info for each file sending job.

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileTransfers {
    /// Size in bytes of a file to transfer.
    pub size: u64,
    /// Size in bytes of a file already transferred.
    pub transferred: u64,
    /// Status of transferring.
    pub status: TransferStatus,
    /// Status of pausing.
    pub pause: PauseStatus,
    /// Number of last packet sent.
    pub last_packet_number: u32,
    /// Data requested by the request chunk callback.
    pub requested: u64,
    /// Unique file id for this transfer.
    pub unique_id: FileUID,
}

impl FileTransfers {
    /// Make new FileTransfers object
    pub fn new() -> Self {
        FileTransfers {
            size: 0,
            transferred: 0,
            status: TransferStatus::NotAccepted,
            pause: PauseStatus::FT_NONE,
            last_packet_number: 0,
            requested: 0,
            unique_id: FileUID::new(),
        }
    }
}

#[derive(Clone, Debug)]
struct Friend {
    /// Number of files sending.
    num_sending_files: u8,
    /// File transfer objects for sending.
    files_sending: Vec<Option<FileTransfers>>,
    /// File transfer objects for receiving.
    files_receiving: Vec<Option<FileTransfers>>,
}

impl Friend {
    pub fn new() -> Self {
        Friend {
            num_sending_files: 0,
            files_receiving: Vec::new(),
            files_sending: Vec::new(),
        }
    }
}

/// FileSending object
#[derive(Clone)]
pub struct FileSending {
    /// Friends who are transferring files with us.
    friends: Arc<RwLock<HashMap<PublicKey, Friend>>>,
    friend_connections: FriendConnections,
    /// NetCrypto object
    net_crypto: NetCrypto,
    /// Sink for file control packets
    recv_file_control_tx: UnboundedSender<(PublicKey, FileTransferPacket)>,
    /// Sink for file data packets, `u64` is for file position which is a offset from the beginning of file.
    recv_file_data_tx: Sender<(PublicKey, FileTransferPacket, u64)>,
}

impl FileSending {
    /// Create new FileSending object
    pub fn new(
        friend_connections: FriendConnections,
        net_crypto: NetCrypto,
        recv_file_control_tx: UnboundedSender<(PublicKey, FileTransferPacket)>,
        recv_file_data_tx: Sender<(PublicKey, FileTransferPacket, u64)>,
    ) -> Self {
        FileSending {
            friends: Arc::new(RwLock::new(HashMap::new())),
            friend_connections,
            net_crypto,
            recv_file_control_tx,
            recv_file_data_tx,
        }
    }

    /// Send file control request.
    /// File control packet does some control action like Accept, Kill, Seek, Pause.
    async fn send_file_control_packet(&self, pk: PublicKey, dir: TransferDirection, file_id: u8, control: ControlType)
                                -> Result<(), SendPacketError> {
        let packet = FileControl::new(dir, file_id, control);
        let mut buf = [0; MAX_CRYPTO_DATA_SIZE];
        match packet.to_bytes((&mut buf, 0)) {
            Ok((data, size)) => {
                trace!("send file control packet {:?}", data[..size].to_vec().clone());
                self.net_crypto.send_lossless(pk, data[..size].to_vec())
                    .map_err(|e| SendPacketError::from(e)).await
            },
            Err(e) => {
                trace!("send control packet error {:?}", e);
                Err(SendPacketError::serialize(e))
            },
        }
    }

    async fn get_friend(&self, friend_pk: PublicKey) -> Result<Friend, SendPacketError> {
        let mut friends = self.friends.write().await;
        friends.get(&friend_pk)
            .map_or_else(
                || Err(SendPacketErrorKind::NoFriend.into()),
                |friend| Ok(friend.clone()))
    }

    /// Add a friend to prepare transferring files.
    pub async fn add_friend(&self, friend_pk: PublicKey) {
        let mut friends = self.friends.write().await;
        friends.insert(friend_pk, Friend::new());
    }

    /// Issue seek file control request
    /// This packet is for adjust the offset which is being transferred.
    /// Adjusting offset is needed for loss of file data packet while transferring.
    pub async fn send_file_seek(&self, friend_pk: PublicKey, file_id: u8, position: u64) -> Result<(), SendPacketError> {
        let mut friend = match self.get_friend(friend_pk).await {
            Ok(friend) => friend,
            Err(e) => return Err(e);
        };

        if let Ok(status) = self.friend_connections.get_connection_status(friend_pk).await {
            if !status {
                return Err(SendPacketErrorKind::NotOnline.into())
            }
        } else {
            return Err(SendPacketErrorKind::NotOnline.into())
        }

        let files_receiving = friend.files_receiving.clone();
        let ft = if let Some(ft) = files_receiving.get(file_id as usize) {
            ft
        } else {
            return Err(SendPacketErrorKind::NoFileTransfer.into())
        };

        let ft = if let Some(ft) = ft {
            ft
        } else {
            return Err(SendPacketErrorKind::NoFileTransfer.into())
        };

        if ft.status != TransferStatus::NotAccepted {
            return Err(SendPacketErrorKind::NotAccepted.into())
        }

        if position >= ft.size {
            return Err(SendPacketErrorKind::LargerPosition.into())
        }

        let mut ft_c = ft.clone();
        self.send_file_control_packet(friend_pk, TransferDirection::Receive, file_id, ControlType::Seek(position)).await;
        ft_c.transferred = position;
        friend.files_receiving[file_id as usize] = Some(ft_c);
        Ok(())
    }

    /// Issue file control request.
    pub async fn send_file_control(&self, friend_pk: PublicKey, file_id: u8, dir: TransferDirection, control: ControlType)
                             -> Result<(), SendPacketError> {
        let mut friend = match self.get_friend(friend_pk).await {
            Ok(friend) => friend,
            Err(e) => return Err(e)
        };

        if let Ok(status) = self.friend_connections.get_connection_status(friend_pk) {
            if !status {
                return Err(SendPacketErrorKind::NotOnline.into())
            }
        } else {
            return Err(SendPacketErrorKind::NotOnline.into())
        }

        let files = if dir == TransferDirection::Send {
            friend.files_sending.clone()
        } else {
            friend.files_receiving.clone()
        };

        let ft = if let Some(ft) = files.get(file_id as usize)
        {
            ft
        } else {
            return Err(SendPacketErrorKind::NoFileTransfer.into())
        };

        let ft = if let Some(ft) = ft {
            ft
        } else {
            return Err(SendPacketErrorKind::NoFileTransfer.into())
        };

        if ft.status != TransferStatus::NotAccepted {
            return Err(SendPacketErrorKind::NotAccepted.into())
        }

        if control == ControlType::Pause && (ft.pause & PauseStatus::US == PauseStatus::US || ft.status != TransferStatus::Transferring) {
            return Err(SendPacketErrorKind::InvalidRequest.into())
        }

        if control == ControlType::Accept {
            if ft.status == TransferStatus::Transferring {
                if !(ft.pause & PauseStatus::US == PauseStatus::US) {
                    if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                        return Err(SendPacketErrorKind::InvalidRequest2.into())
                    }
                    return Err(SendPacketErrorKind::InvalidRequest3.into())
                }
            } else {
                if ft.status != TransferStatus::NotAccepted {
                    return Err(SendPacketErrorKind::InvalidRequest4.into())
                }
                if dir == TransferDirection::Send {
                    return Err(SendPacketErrorKind::InvalidRequest5.into())
                }
            }

            self.send_file_control_packet(friend_pk, dir, file_id, control).await;
        }

        let mut ft_c = ft.clone();
        let mut changed_ft = None;
        if control == ControlType::Kill {
            if dir == TransferDirection::Send {
                friend.num_sending_files = friend.num_sending_files.sub(1);
            }
        } else if control == ControlType::Pause {
            ft_c.pause = ft_c.pause | PauseStatus::US;
            changed_ft = Some(ft_c);
        } else if control == ControlType::Accept {
            ft_c.status = TransferStatus::Transferring;
            changed_ft = Some(ft_c.clone());

            if ft_c.pause & PauseStatus::US == PauseStatus::US {
                ft_c.pause = ft_c.pause ^ PauseStatus::US;
                changed_ft = Some(ft_c.clone());
            }
        }

        if dir == TransferDirection::Send {
            friend.files_sending[file_id as usize] = changed_ft;
        } else {
            friend.files_receiving[file_id as usize] = changed_ft;
        }

        Ok(())
    }

    async fn recv_from(&self, friend_pk: PublicKey, packet: FileTransferPacket) -> Result<(), RecvPacketError> {
        let tx = self.recv_file_control_tx.clone();
        send_to(&tx, (friend_pk, packet)).await
            .map_err(RecvPacketError::from)
    }

    async fn recv_from_data(&self, friend_pk: PublicKey, packet: FileTransferPacket, position: u64) -> Result<(), Error=RecvPacketError> {
        let tx = self.recv_file_data_tx.clone();
        send_to(&tx, (friend_pk, packet, position)).await
            .map_err(RecvPacketError::from)
    }

    async fn send_req_kill(&self, friend_pk: PublicKey, file_id: u8, transfer_direction: TransferDirection, control_type: ControlType)
                     -> Result<(), RecvPacketError> {
        self.send_file_control_packet(friend_pk, transfer_direction, file_id, control_type)
            .map_err(RecvPacketError::from).await
    }

    /// Handle file control request packet
    pub async fn handle_file_control(&self, friend_pk: PublicKey, packet: FileControl)
                               -> Result<(), RecvPacketError> {
        let mut friend = match self.get_friend(friend_pk).await {
            Ok(friend) => friend,
            Err(e) => return Err(e.into())
        };

        let mut files = if packet.transfer_direction == TransferDirection::Send {
            friend.files_sending.clone()
        } else {
            friend.files_receiving.clone()
        };

        let ft = if let Some(ft) = files.get_mut(packet.file_id as usize)
        {
            ft
        } else {
            let packet_c = packet.clone();
            warn!("file control (friend {:?}, file {}): file transfer does not exist; telling the other to kill it", friend_pk, packet_c.file_id);
            return self.send_req_kill(friend_pk, packet_c.file_id, packet_c.transfer_direction.toggle(), ControlType::Kill).await
        };

        let mut ft = if let Some(ft) = ft {
            ft
        } else {
            return Err(RecvPacketErrorKind::NoFileTransfer.into());
        };

        let up_packet = FileTransferPacket::FileControl(packet.clone());

        if packet.control_type == ControlType::Accept {
            if packet.transfer_direction == TransferDirection::Receive && ft.status == TransferStatus::NotAccepted {
                ft.status = TransferStatus::Transferring;
            } else {
                if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER {
                    ft.pause = ft.pause ^ PauseStatus::OTHER;
                } else {
                    warn!("file control (friend {:?}, file {}): friend told us to resume file transfer that wasn't paused", friend_pk, packet.file_id);
                    return Err(RecvPacketError::invalid_request(friend_pk, packet.file_id))
                }
            }
        } else if packet.control_type == ControlType::Pause {
            if ft.pause & PauseStatus::OTHER == PauseStatus::OTHER || ft.status != TransferStatus::Transferring {
                warn!("file control (friend {:?}, file {}): friend told us to pause file transfer that is already paused", friend_pk, packet.file_id);
                return Err(RecvPacketError::invalid_request(friend_pk, packet.file_id));
            }

            ft.pause = ft.pause | PauseStatus::OTHER;
        } else if packet.control_type == ControlType::Kill {
            if packet.transfer_direction == TransferDirection::Receive {
                friend.num_sending_files = friend.num_sending_files.sub(1);
                friend.files_receiving[packet.file_id as usize] = None;
            } else {
                friend.files_sending[packet.file_id as usize] = None;
            }
        } else if let ControlType::Seek(position) = packet.control_type {
            if ft.status != TransferStatus::NotAccepted || packet.transfer_direction == TransferDirection::Send {
                warn!("file control (friend {:?}, file {}): seek was either sent by a sender or by the receiver after accepting", friend_pk, packet.file_id);
                return Err(RecvPacketError::invalid_request(friend_pk, packet.file_id));
            }
            if position >= ft.size {
                warn!("file control (friend {:?}, file {}): seek position {} exceeds file size {}", friend_pk, packet.file_id, position, ft.size);
                return Err(RecvPacketError::exceed_size(friend_pk, packet.file_id, ft.size));
            }
            ft.requested = position;
            ft.transferred = position;
        } else { // unknown file control
            return Err(RecvPacketErrorKind::UnknownControlType.into());
        }

        self.recv_from(friend_pk, up_packet).await
    }

    /// Handle file send request packet
    pub async fn handle_file_send_request(&self, friend_pk: PublicKey, packet: FileSendRequest)
                                    -> Result<(), RecvPacketError> {
        let mut friend = match self.get_friend(friend_pk).await {
            Ok(friend) => friend,
            Err(e) => return Err(e.into())
        };

        let files_receiving = friend.files_receiving.clone();
        if None == files_receiving.get(packet.file_id as usize) {
            return Err(RecvPacketErrorKind::NoFileTransfer.into())
        }

        let mut ft = FileTransfers::new();

        ft.status = TransferStatus::NotAccepted;
        ft.size = packet.file_size;
        ft.transferred = 0;
        ft.pause = PauseStatus::FT_NONE;

        friend.files_receiving[packet.file_id as usize] = Some(ft);

        self.recv_from(friend_pk, FileTransferPacket::FileSendRequest(packet)).await
    }

    /// Handle file data packet
    pub async fn handle_file_data(&self, friend_pk: PublicKey, packet: FileData)
                            -> Result<(), RecvPacketError> {
        let friend = match self.get_friend(friend_pk).await {
            Ok(friend) => friend,
            Err(e) => return Err(e.into())
        };

        let mut files_receiving = friend.files_receiving.clone();
        let ft = if let Some(ft) = files_receiving.get_mut(packet.file_id as usize) {
            ft
        } else {
            return Err(RecvPacketErrorKind::NoFileTransfer.into())
        };

        let ft = if let Some(ft) = ft {
            ft
        } else {
            return Err(RecvPacketErrorKind::NoFileTransfer.into())
        };

        if ft.status != TransferStatus::Transferring {
            return Err(RecvPacketErrorKind::NotTransferring.into())
        }

        let mut data_len = packet.data.len() as u64;
        let position = ft.transferred;

        let mut packet = packet;

        // Prevent more data than the filesize from being passed to clients.
        if ft.transferred + data_len > ft.size {
            data_len = ft.size - ft.transferred;
            packet.data.drain(..data_len as usize);
        }

        ft.transferred = ft.transferred.add(data_len);

        let up_packet = FileTransferPacket::FileData(packet.clone());

        let ft_c = ft.clone();
        let mut friend_c = friend.clone();
        self.recv_from_data(friend_pk, up_packet, position).await;
        if data_len == 0 {
            friend_c.files_receiving[packet.file_id as usize] = None;
        }

        if data_len > 0 && (ft_c.transferred >= ft_c.size || data_len != MAX_FILE_DATA_SIZE as u64) {
            let packet = FileTransferPacket::FileData(FileData::new(packet.file_id, Vec::new()));
            self.recv_from_data(friend_pk, packet, position).await
        } else {
            Ok(())
        }
    }
}

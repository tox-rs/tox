use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tox_crypto::increment_nonce_number;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("0xff00 + 0x0110", |b| b.iter(|| {
        let mut nonce = [0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0xff, 0];
        increment_nonce_number(&mut nonce, black_box(0x01_10));
    }));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

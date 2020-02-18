//! `error_kind` macros that helps to construct errors using Error-ErrorKind
//! pair pattern.

/// Helps to construct errors using Error-ErrorKind pair pattern.
macro_rules! error_kind {
    ($(#[$error_attr:meta])* $error:ident, $(#[$kind_attr:meta])* $kind:ident { $($variants:tt)* }) => {
        $(#[$error_attr])*
        pub struct $error {
            ctx: failure::Context<$kind>,
        }

        impl $error {
            /// Return the kind of this error.
            #[allow(dead_code)] // might be unused if error is private
            pub fn kind(&self) -> &$kind {
                self.ctx.get_context()
            }
        }

        impl failure::Fail for $error {
            fn cause(&self) -> Option<&dyn failure::Fail> {
                self.ctx.cause()
            }

            fn backtrace(&self) -> Option<&failure::Backtrace> {
                self.ctx.backtrace()
            }
        }

        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                self.ctx.fmt(f)
            }
        }

        $(#[$kind_attr])*
        pub enum $kind {
            $($variants)*
        }

        impl From<$kind> for $error {
            fn from(kind: $kind) -> $error {
                $error::from(failure::Context::new(kind))
            }
        }

        impl From<failure::Context<$kind>> for $error {
            fn from(ctx: failure::Context<$kind>) -> $error {
                $error { ctx }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use failure::Fail;

    error_kind! {
        #[derive(Debug)]
        TestError,
        #[derive(Clone, Debug, Eq, PartialEq, Fail)]
        TestErrorKind {
            #[fail(display = "Variant1")]
            Variant1,
            #[fail(display = "Variant2")]
            Variant2,
        }
    }

    #[test]
    fn test_error() {
        assert_eq!(format!("{}", TestErrorKind::Variant1), "Variant1".to_owned());
        assert_eq!(format!("{}", TestErrorKind::Variant2), "Variant2".to_owned());
    }

    #[test]
    fn test_error_variant_1() {
        let error = TestError::from(TestErrorKind::Variant1);
        assert_eq!(error.kind(), &TestErrorKind::Variant1);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Variant1".to_owned());
    }

    #[test]
    fn test_error_variant_2() {
        let error = TestError::from(TestErrorKind::Variant2);
        assert_eq!(error.kind(), &TestErrorKind::Variant2);
        assert!(error.cause().is_none());
        assert!(error.backtrace().is_some());
        assert_eq!(format!("{}", error), "Variant2".to_owned());
    }
}

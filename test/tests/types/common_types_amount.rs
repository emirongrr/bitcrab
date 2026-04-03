use bitcrab_common::types::amount::*;


    #[test]
    fn max_money_is_accepted() {
        assert!(Amount::from_sat(MAX_MONEY).is_ok());
    }

    #[test]
    fn one_above_max_is_rejected() {
        let err = Amount::from_sat(MAX_MONEY + 1).unwrap_err();
        assert!(matches!(err, AmountError::ExceedsMaxMoney(_)));
        assert!(err.to_string().contains("MAX_MONEY"));
    }

    #[test]
    fn checked_add_stops_at_max() {
        assert!(Amount::MAX.checked_add(Amount::from_sat(1).unwrap()).is_none());
    }

    #[test]
    fn checked_sub_no_underflow() {
        let a = Amount::from_sat(5).unwrap();
        let b = Amount::from_sat(10).unwrap();
        assert!(a.checked_sub(b).is_none());
    }

    #[test]
    fn display_one_bitcoin() {
        assert_eq!(Amount::ONE_BTC.to_string(), "1.00000000 BTC");
    }

    #[test]
    fn fee_pattern() {
        let inputs  = Amount::from_sat(100_000).unwrap();
        let outputs = Amount::from_sat(99_000).unwrap();
        let fee = inputs.checked_sub(outputs).unwrap();
        assert_eq!(fee.to_sat(), 1_000);
    }

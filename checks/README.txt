$Id: README.txt 225 2010-05-13 07:18:55Z jakob $

# Test environment for the ICANN Key Management Toolset


## SoftHSM Configuration

The test environment use SoftHSM as its PKCS#11 provider. Two configurations
are available; one slot with two keys (to simulate one HSM) and two slots with
one key each (to simulate rollover between two HSM:s).


### One slot with two keys (softhsm-single.conf)

#### Provider Configuration

    SOFTHSM_CONF=softhsm-single.conf pkcs11-tool \
        --module=/usr/local/lib/libsofthsm.so \
        --list-slots

    Available slots:
    Slot 0           SoftHSM
      token label:   softHSM
      token manuf:   SoftHSM
      token model:   SoftHSM
      token flags:   rng, login required, PIN initialized, token initialized, other flags=0x40
      serial num  : 1

#### Token Inventory, slot 0

    SOFTHSM_CONF=softhsm-single.conf pkcs11-tool \
        --module=/usr/local/lib/libsofthsm.so \
        --list-objects --login --pin=123456 --slot 0
    
    Public Key Object; RSA 2048 bits
      label:      KSK2
      ID:         02
      Usage:      verify
    Private Key Object; RSA 
      label:      KSK2
      ID:         02
      Usage:      sign
    Public Key Object; RSA 2048 bits
      label:      KSK1
      ID:         01
      Usage:      verify
    Private Key Object; RSA 
      label:      KSK1
      ID:         01
      Usage:      sign


### Two slots with one key each (softhsm-dual.conf)

#### Provider Configuration

    SOFTHSM_CONF=softhsm-dual.conf pkcs11-tool \
        --module=/usr/local/lib/libsofthsm.so \
        --list-slots
    
    Available slots:
    Slot 1           SoftHSM
      token label:   softHSM
      token manuf:   SoftHSM
      token model:   SoftHSM
      token flags:   rng, login required, PIN initialized, token initialized, other flags=0x40
      serial num  :  1
    Slot 2           SoftHSM
      token label:   softHSM
      token manuf:   SoftHSM
      token model:   SoftHSM
      token flags:   rng, login required, PIN initialized, token initialized, other flags=0x40
      serial num  :  1

#### Token Inventory, slot 1

    SOFTHSM_CONF=softhsm-dual.conf pkcs11-tool \
        --module=/usr/local/lib/libsofthsm.so \
        --list-objects --login --pin=123456 --slot 1
    
    Public Key Object; RSA 2048 bits
      label:      KSK1
      ID:         01
      Usage:      verify
    Private Key Object; RSA 
      label:      KSK1
      ID:         01
      Usage:      sign

#### Token Inventory, slot 2

    SOFTHSM_CONF=softhsm-dual.conf pkcs11-tool \
        --module=/usr/local/lib/libsofthsm.so \
        --list-objects --login --pin=123456 --slot 2
    
    Public Key Object; RSA 2048 bits
      label:      KSK2
      ID:         02
      Usage:      verify
    Private Key Object; RSA 
      label:      KSK2
      ID:         02
      Usage:      sign

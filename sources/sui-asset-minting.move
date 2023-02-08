module sui_asset_minting::asset_minting {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::ecdsa_k1::{Self};
    use sui::event;
    use sui::url;

    use std::vector;
    use std::string::{Self, String};

    use nft_protocol::nft;
    use nft_protocol::tags;
    use nft_protocol::royalty;
    use nft_protocol::display;
    use nft_protocol::creators;
    use nft_protocol::collection::{Self,  MintCap};

    /// Colection And NFT

    /// Can be used for authorization of other actions post-creation. It is
    /// vital that this struct is not freely given to any contract, because it
    /// serves as an auth token.
    struct Witness has drop {}

    public entry fun create_collection( ctx: &mut TxContext) {

        let witness = Witness{};

        let (mint_cap, collection) = collection::create(
            &witness, ctx
        );

        collection::add_domain(
            &mut collection,
            &mut mint_cap,
            creators::from_address(tx_context::sender(ctx), ctx)
        );

        // Register custom domains
        display::add_collection_display_domain(
            &mut collection,
            &mut mint_cap,
            string::utf8(b"Suimarines"),
            string::utf8(b"A unique NFT collection of Suimarines on Sui"),
            ctx
        );

        display::add_collection_url_domain(
            &mut collection,
            &mut mint_cap,
            sui::url::new_unsafe_from_bytes(b"https://originbyte.io/"),
            ctx
        );

        display::add_collection_symbol_domain(
            &mut collection,
            &mut mint_cap,
            string::utf8(b"SUIM"),
            ctx
        );

        let royalty = royalty::from_address(tx_context::sender(ctx) ,ctx);
        royalty::add_proportional_royalty(
            &mut royalty,
            100,
        );
        royalty::add_royalty_domain(&mut collection, &mut mint_cap, royalty);

        let tags = tags::empty(ctx);
        tags::add_tag(&mut tags, tags::art());
        tags::add_collection_tag_domain(&mut collection, &mut mint_cap, tags);

        transfer::transfer(mint_cap, tx_context::sender(ctx));
        transfer::share_object(collection);
    }

    public entry fun create_collection_with_data(collectionName: vector<u8>, collectionSymbole: vector<u8>, collectionDiscription: vector<u8>,
                                                 collectionUrl: vector<u8>, ctx: &mut TxContext) {

        let witness = Witness{};

        let (mint_cap, collection) = collection::create(
            &witness, ctx
        );

        collection::add_domain(
            &mut collection,
            &mut mint_cap,
            creators::from_address(tx_context::sender(ctx), ctx)
        );

        // Register custom domains
        display::add_collection_display_domain(
            &mut collection,
            &mut mint_cap,
            string::utf8(collectionName),
            string::utf8(collectionDiscription),
            ctx
        );

        display::add_collection_url_domain(
            &mut collection,
            &mut mint_cap,
            sui::url::new_unsafe_from_bytes(collectionUrl),
            ctx
        );

        display::add_collection_symbol_domain(
            &mut collection,
            &mut mint_cap,
            string::utf8(collectionSymbole),
            ctx
        );

        let royalty = royalty::from_address(tx_context::sender(ctx) ,ctx);
        royalty::add_proportional_royalty(
            &mut royalty,
            100,
        );
        royalty::add_royalty_domain(&mut collection, &mut mint_cap, royalty);

        let tags = tags::empty(ctx);
        tags::add_tag(&mut tags, tags::art());
        tags::add_collection_tag_domain(&mut collection, &mut mint_cap, tags);

        transfer::transfer(mint_cap, tx_context::sender(ctx));
        transfer::share_object(collection);
    }

    public entry fun create_nft(name: vector<u8>, description: vector<u8>, url: vector<u8>,
                                attribute_keys: vector<String>,
                                attribute_values: vector<String>,
                                _mint_cap: &MintCap<Witness>,
                                ctx: &mut TxContext) {

        let nft = nft::new<Witness, Witness>(
            &Witness {}, tx_context::sender(ctx), ctx
        );

        display::add_display_domain(
            &mut nft,
            string::utf8(name),
            string::utf8(description),
            ctx,
        );

        display::add_url_domain(
            &mut nft,
            url::new_unsafe_from_bytes(url),
            ctx,
        );

        display::add_attributes_domain_from_vec(
            &mut nft,
            attribute_keys,
            attribute_values,
            ctx,
        );

        transfer::transfer(nft, tx_context::sender(ctx))
    }

    public entry fun create_nft_without(name: vector<u8>, description: vector<u8>, url: vector<u8>,
                                ctx: &mut TxContext) {

        let nft = nft::new<Witness, Witness>(
            &Witness {}, tx_context::sender(ctx), ctx
        );

        display::add_display_domain(
            &mut nft,
            string::utf8(name),
            string::utf8(description),
            ctx,
        );

        display::add_url_domain(
            &mut nft,
            url::new_unsafe_from_bytes(url),
            ctx,
        );

        transfer::transfer(nft, tx_context::sender(ctx))
    }

    struct SuperAdminCap has key {
        id: UID
    }

    struct SuperAdminConfig has key {
        id: UID,
        cap: address,
        singer: address,
        owner: address
    }

    struct AdminCap has key {
        id: UID
    }

    struct AdminConfig has key {
        id: UID,
        cap: address,
        signer: address,
        owner: address
    }

    fun init(ctx: &mut TxContext) {
        let supperAdminCap: SuperAdminCap = SuperAdminCap {
            id: object::new(ctx)
        };

        let mainConfig: SuperAdminConfig = SuperAdminConfig {
            id: object::new(ctx),
            singer: tx_context::sender(ctx),
            cap: object::uid_to_address(&supperAdminCap.id),
            owner: tx_context::sender(ctx)
        };

        transfer::transfer(supperAdminCap, tx_context::sender(ctx));

        transfer::share_object(mainConfig)
    }

    public entry fun create_admin(_: &SuperAdminCap, signer: address, owner: address, ctx: &mut TxContext) {
        let adminCap: AdminCap = AdminCap {
            id: object::new(ctx)
        };

        let adminConfig: AdminConfig = AdminConfig {
            id: object::new(ctx),
            cap: object::uid_to_address(&adminCap.id),
            signer,
            owner
        };

        transfer::transfer(adminCap, owner);

        transfer::share_object(adminConfig)
    }


    /// An error occurred while deserializing, for example due to wrong input size.
    const E_DESERIALIZE: u64 = 1;

    struct Address has store, drop, copy {
        bytes: vector<u8>
    }

    /// Deserializes a raw byte sequence into an address.
    /// Aborts if the input is not 20 bytes long.
    public fun from_bytes(bytes: vector<u8>): Address {
        assert!(std::vector::length(&bytes) == 20, E_DESERIALIZE);
        Address { bytes }
    }

    /// Computes the address from a 64 byte public key.
    public fun from_pubkey(pubkey: vector<u8>): Address {
        assert!(std::vector::length(&pubkey) == 64, E_DESERIALIZE);
        let hash = ecdsa_k1::keccak256(&pubkey);
        let address = vector::empty<u8>();
        let i = 0;
        while (i < 20) {
            vector::push_back(&mut address, vector::pop_back(&mut hash));
            i = i + 1;
        };
        vector::reverse(&mut address);
        Address { bytes: address }
    }

    /// Recovers the address from a signature and message.
    /// This is known as 'ecrecover' in EVM.
    public fun from_signature(
        message: vector<u8>,
        recovery_id: u8,
        sig: vector<u8>,
    ): Address {
        // sui's ecrecover function takes a 65 byte array (signature + recovery byte)
        vector::push_back(&mut sig, recovery_id);

        let pubkey = ecdsa_k1::ecrecover(&sig, &message);
        let pubkey = ecdsa_k1::decompress_pubkey(&pubkey);

        // decompress_pubkey returns 65 bytes, the first byte is not relevant to
        // us, so we remove it
        vector::remove(&mut pubkey, 0);

        from_pubkey(pubkey)
    }


    /// Event on whether the signature is verified
    struct VerifiedEvent has copy, drop {
        is_verified: bool,
    }

    /// Object that holds the output data
    struct Output has key, store {
        id: UID,
        value: vector<u8>
    }

    public entry fun keccak256(data: vector<u8>, recipient: address, ctx: &mut TxContext) {
        let hashed = Output {
            id: object::new(ctx),
            value: ecdsa_k1::keccak256(&data),
        };
        // Transfer an output data object holding the hashed data to the recipient.
        transfer::transfer(hashed, recipient)
    }

    public entry fun ecrecover(signature: vector<u8>, hashed_msg: vector<u8>, recipient: address, ctx: &mut TxContext) {

        let v = vector::borrow_mut(&mut signature, 64);
        if (*v == 27) {
            *v = 0;
        } else if (*v == 28) {
            *v = 1;
        } else if (*v > 35) {
            *v = (*v - 1) % 2;
        };

        let pubkey = Output {
            id: object::new(ctx),
            value: ecdsa_k1::ecrecover(&signature, &hashed_msg),
        };
        // Transfer an output data object holding the pubkey to the recipient.
        transfer::transfer(pubkey, recipient)
    }

    public entry fun new_ecrecover(signature: vector<u8>, hashed_msg: vector<u8>, recipient: address, ctx: &mut TxContext) {

        let dd = from_signature(hashed_msg, 0x01, signature);

        let pubkey = Output {
            id: object::new(ctx),
            value: dd.bytes,
        };
        // Transfer an output data object holding the pubkey to the recipient.
        transfer::transfer(pubkey, recipient)
    }

    public entry fun new_new_ecrecover(signature: vector<u8>, hashed_msg: vector<u8>, recipient: address, ctx: &mut TxContext) {

        let dd = from_signature(hashed_msg, 0x00, signature);

        let pubkey = Output {
            id: object::new(ctx),
            value: dd.bytes,
        };
        // Transfer an output data object holding the pubkey to the recipient.
        transfer::transfer(pubkey, recipient)
    }

    public entry fun ecrecover_to_eth_address(signature: vector<u8>, hashed_msg: vector<u8>, recipient: address, ctx: &mut TxContext) {
        // Normalize the last byte of the signature to be 0 or 1.
        let v = vector::borrow_mut(&mut signature, 64);
        if (*v == 27) {
            *v = 0;
        } else if (*v == 28) {
            *v = 1;
        } else if (*v > 35) {
            *v = (*v - 1) % 2;
        };

        let pubkey = ecdsa_k1::ecrecover(&signature, &hashed_msg);
        let uncompressed = ecdsa_k1::decompress_pubkey(&pubkey);

        // Take the last 64 bytes of the uncompressed pubkey.
        let uncompressed_64 = vector::empty<u8>();
        let i = 1;
        while (i < 65) {
            let value = vector::borrow(&uncompressed, i);
            vector::push_back(&mut uncompressed_64, *value);
            i = i + 1;
        };

        // Take the last 20 bytes of the hash of the 64-bytes uncompressed pubkey.
        let hashed = ecdsa_k1::keccak256(&uncompressed_64);
        let addr = vector::empty<u8>();
        let i = 12;
        while (i < 32) {
            let value = vector::borrow(&hashed, i);
            vector::push_back(&mut addr, *value);
            i = i + 1;
        };

        let addr_object = Output {
            id: object::new(ctx),
            value: addr,
        };

        // Transfer an output data object holding the address to the recipient.
        transfer::transfer(addr_object, recipient)
    }

    public entry fun secp256k1_verify(signature: vector<u8>, public_key: vector<u8>, hashed_msg: vector<u8>) {
        event::emit(VerifiedEvent {is_verified: ecdsa_k1::secp256k1_verify(&signature, &public_key, &hashed_msg)});
    }

    // Word

    struct Word has key {
        id: UID,
        word: string::String
    }

    public entry fun create_word(wordVec: vector<u8>, ctx: &mut TxContext) {
        let wordObj: Word = Word {
            id: object::new(ctx),
            word: string::utf8(wordVec)
        };

        transfer::transfer(wordObj, tx_context::sender(ctx))
    }

    public entry fun create_without_word(ctx: &mut TxContext) {
        let wordObj: Word = Word {
            id: object::new(ctx),
            word: string::utf8(b"Sniper")
        };

        transfer::transfer(wordObj, tx_context::sender(ctx))
    }

    // Counter
}

#[test_only]
module sui_asset_minting::asset_minting_test {
    use std::debug;
    use std::string;

    #[test]
    public fun say_hello() {

        let dd = b"hello";
        debug::print(&string::utf8(dd));
    }
}
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/// @title PatientMedicalRecords - patient-controlled medical records registry
/// @notice Stores metadata (IPFS CIDs / content hashes) and per-provider encrypted symmetric keys. 
/// @dev Sensitive content is NOT stored on-chain. Uses events for auditable actions.

contract PatientMedicalRecords {

    struct Record {
        uint256 id;
        string cid;                     //IPFS CID other off-chain             
        bytes32 contentHash;            //keccak256 of the encrypted file (integrity)      
        uint256 timestamp;
        address creator;               //patient address who created the record
        bool exists;

    }
    // For each record, store mapping provider => encrypted symmetric key (bytes) 
    // providerEncryptedKeys[recordId][provider] = encryptedSymKey

    mapping(uint256 => mapping(address => bytes)) public providerEncryptedKeys;
     // recordId => Record
    mapping(uint256 => Record) public records;
     // patient address => list of record IDs owned by patient
    mapping(address => uint256[]) public patientRecords;
    // small counter for record IDs
    uint256 private _recordCounter;
    // Events for audit trail

    event RecordCreated(uint256 indexed recordId, address indexed patient, string cid, uint256 timestamp);
    event ProviderAuthorized(uint256 indexed recordId, address indexed patient, address indexed provider);
    event ProviderRevoked(uint256 indexed recordId, address indexed patient, address indexed provider);
    event RecordDeleted(uint256 indexed recordId, address indexed patient);
    event EncryptedKeyUpdated(uint256 indexed recordId, address indexed provider);

    // Modifiers

    modifier recordExists(uint256 recordId) {
        require(records[recordId].exists, "Record does not exist");
        _;
    }
    /// Create a new medical record metadata entry
    /// @param cid IPFS CID or off-chain reference (e.g., "ipfs://Qm...") 
    /// @param contentHash keccak256 hash of the encrypted file bytes (for integrity checks) 
    /// @param initialProviders array of providers to authorize initially 
    /// @param encryptedKeys array of encrypted symmetric keys corresponding to initialProviders

        function createRecord(
        string calldata cid,
        bytes32 contentHash,
        address[] calldata initialProviders,
        bytes[] calldata encryptedKeys
    ) external returns (uint256) {
        require(initialProviders.length == encryptedKeys.length, "Providers & keys length mismatch");

        _recordCounter += 1;
        uint256 rid = _recordCounter;

        records[rid] = Record({
            id: rid,
            cid: cid,
            contentHash: contentHash,
            timestamp: block.timestamp,
            creator: msg.sender,
            exists: true
        });

     
            // store encrypted keys for each initial provider
        for (uint i = 0; i < initialProviders.length; i++) {
            providerEncryptedKeys[rid][initialProviders[i]] = encryptedKeys[i];
            emit EncryptedKeyUpdated(rid, initialProviders[i]);
            emit ProviderAuthorized(rid, msg.sender, initialProviders[i]);
        }

        patientRecords[msg.sender].push(rid);

        emit RecordCreated(rid, msg.sender, cid, block.timestamp);
        return rid;
    }
       /// Patient authorizes a provider by setting an encrypted symmetric key for that provider 
       /// @param recordId record to authorize 
       /// @param provider provider address to authorize 
       /// @param encryptedKey symmetric key encrypted with provider's public key (bytes)

    function authorizeProvider(uint256 recordId, address provider, bytes calldata encryptedKey)
        external
        recordExists(recordId)
            {
        require(msg.sender == records[recordId].creator, "Only patient can authorize provider");
        providerEncryptedKeys[recordId][provider] = encryptedKey;
        emit ProviderAuthorized(recordId, msg.sender, provider);
        emit EncryptedKeyUpdated(recordId, provider);
    }
       /// Patient revokes provider access 
       /// @param recordId record to revoke 
       /// @param provider provider address to revoke

      function revokeProvider(uint256 recordId, address provider)
        external
        recordExists(recordId)
    {
        require(msg.sender == records[recordId].creator, "Only patient can revoke provider");
        delete providerEncryptedKeys[recordId][provider];
        emit ProviderRevoked(recordId, msg.sender, provider);
    }

       // Returns the encrypted key for the caller tied to a specific record.
    // Only the caller’s own encrypted key is returned.
    function getEncryptedKeyForCaller(uint256 recordId)
        external
        view
        recordExists(recordId)
        returns (bytes memory)
    {
        return providerEncryptedKeys[recordId][msg.sender];
    }

    // Returns metadata for a given medical record:
    // - cid: IPFS or storage identifier
    // - contentHash: hash of the record content for integrity verification
    // - timestamp: when the record was created
    // - creator: address that originally created the record
    function getRecordMetadata(uint256 recordId)
        external
        view
        recordExists(recordId)
        returns (string memory cid, bytes32 contentHash, uint256 timestamp, address creator)
    {
        Record storage r = records[recordId];
        return (r.cid, r.contentHash, r.timestamp, r.creator);
    }

    // Soft-deletes a record. Only the creator (patient) can delete it.
    // The record data remains stored for auditability, but `exists` is set to false.
    function deleteRecord(uint256 recordId) external recordExists(recordId) {
        require(msg.sender == records[recordId].creator, "Only patient can delete record");
        
        // Mark record as no longer existing
        records[recordId].exists = false;

        emit RecordDeleted(recordId, msg.sender);
    }

    // Recovers the signer address from a hashed message and ECDSA signature.
    // Useful for verifying off-chain signatures.
    function recoverSigner(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
        public
        pure
        returns (address)
    {
        return ecrecover(messageHash, v, r, s);
    }

    // Returns all record IDs associated with a patient.
    // Helpful for listing a patient’s stored medical records.
    function getPatientRecordIds(address patient) external view returns (uint256[] memory) {
        return patientRecords[patient];
    }
}
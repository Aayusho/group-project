// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract PatientMedicalRecords {

    struct Record {
        uint256 id;
        string cid;                    
        bytes32 contentHash;          
        uint256 timestamp;
        address creator;               // patient address who created the record
        bool exists;

    }

    mapping(uint256 => mapping(address => bytes)) public providerEncryptedKeys;

    mapping(uint256 => Record) public records;
    mapping(address => uint256[]) public patientRecords;
    uint256 private _recordCounter;

    event RecordCreated(uint256 indexed recordId, address indexed patient, string cid, uint256 timestamp);
    event ProviderAuthorized(uint256 indexed recordId, address indexed patient, address indexed provider);
    event ProviderRevoked(uint256 indexed recordId, address indexed patient, address indexed provider);
    event RecordDeleted(uint256 indexed recordId, address indexed patient);
    event EncryptedKeyUpdated(uint256 indexed recordId, address indexed provider);

    modifier recordExists(uint256 recordId) {
        require(records[recordId].exists, "Record does not exist");
        _;
    }

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

    function authorizeProvider(uint256 recordId, address provider, bytes calldata encryptedKey)
        external
        recordExists(recordId)
            {
        require(msg.sender == records[recordId].creator, "Only patient can authorize provider");
        providerEncryptedKeys[recordId][provider] = encryptedKey;
        emit ProviderAuthorized(recordId, msg.sender, provider);
        emit EncryptedKeyUpdated(recordId, provider);
    }

      function revokeProvider(uint256 recordId, address provider)
        external
        recordExists(recordId)
    {
        require(msg.sender == records[recordId].creator, "Only patient can revoke provider");
        delete providerEncryptedKeys[recordId][provider];
        emit ProviderRevoked(recordId, msg.sender, provider);
    }

     function getEncryptedKeyForCaller(uint256 recordId) external view recordExists(recordId) returns (bytes memory) {
        return providerEncryptedKeys[recordId][msg.sender];
    }




    }
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

}

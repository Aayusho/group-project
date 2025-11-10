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
}

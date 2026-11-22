// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract VehicleHistory is Ownable {

    enum IssuerRole { None, Workshop, Insurance, Dealer, Notary }
    
    struct ServiceRecord {
        uint256 timestamp;
        uint256 mileage;
        string description;
        address issuer;
    }

    struct IncidentRecord {
        uint256 timestamp;
        string incidentType;
        string description;
        address issuer;
    }

    struct Vehicle {
        bool exists;
        address currentOwner;
        uint256 lastMileage;
    }

    mapping(address => IssuerRole) public authorizedIssuers;
    mapping(bytes32 => Vehicle) public vehicles;
    mapping(bytes32 => ServiceRecord[]) public serviceHistory;
    mapping(bytes32 => IncidentRecord[]) public incidentHistory;
    mapping(bytes32 => address[]) public ownershipHistory;

    // ===== Merkle allowlist =====
    bytes32 public allowlistRoot;                  
    string public allowlistURI;                   
    mapping(bytes32 => bool) public leafUsed;
    mapping(address => bytes32) public issuerDocHash;

    event IssuerRoleSet(address indexed issuer, IssuerRole role);
    event VehicleRegistered(bytes32 indexed vinHash, address indexed initialOwner, uint256 initialMileage);
    event ServiceAdded(bytes32 indexed vinHash, uint256 mileage, address indexed issuer);
    event IncidentAdded(bytes32 indexed vinHash, string incidentType, address indexed issuer);
    event MileageCorrected(bytes32 indexed vinHash, uint256 newMileage, string reason, address indexed correctedBy);
    event OwnershipTransferred(bytes32 indexed vinHash, address indexed from, address indexed to);

    event AllowlistUpdated(bytes32 indexed root, string uri);
    event RoleClaimed(address indexed issuer, IssuerRole role, bytes32 docHash);
    event RoleRevoked(address indexed issuer);

    constructor() Ownable(msg.sender) {}

    modifier onlyIssuer(IssuerRole role) {
        require(authorizedIssuers[msg.sender] == role, "This Address is not authorized to perform this action !");
        _;
    }

    function setAllowlist(bytes32 root, string calldata uri) external onlyOwner {
        allowlistRoot = root;
        allowlistURI = uri;

        emit AllowlistUpdated(root, uri);
    }

    function _leaf(address account, IssuerRole role, bytes32 docHash) internal pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(account, uint8(role), docHash))));
    }

    function verifyClaim(address account, IssuerRole role, bytes32 docHash, bytes32[] calldata proof)
        public
        view
        returns (bool ok, string memory reason)
    {
        if (allowlistRoot == bytes32(0)) return (false, "Allowlist not set");
        if (role == IssuerRole.None) return (false, "Invalid role");
        if (authorizedIssuers[account] != IssuerRole.None) return (false, "Address already has a role");

        bytes32 leaf = _leaf(account, role, docHash);
        if (leafUsed[leaf]) return (false, "Claim already used");
        if (!MerkleProof.verifyCalldata(proof, allowlistRoot, leaf)) return (false, "Invalid proof");

        return (true, "");
    }

    function claimRole(IssuerRole role, bytes32 docHash, bytes32[] calldata proof) external {
        (bool ok, string memory reason) = verifyClaim(msg.sender, role, docHash, proof);
        require(ok, reason);

        leafUsed[_leaf(msg.sender, role, docHash)] = true;
        authorizedIssuers[msg.sender] = role;
        issuerDocHash[msg.sender] = docHash;

        emit IssuerRoleSet(msg.sender, role);
        emit RoleClaimed(msg.sender, role, docHash);
    }

    function revokeRole(address issuer) external onlyOwner {
        require(authorizedIssuers[issuer] != IssuerRole.None, "No active role");

        authorizedIssuers[issuer] = IssuerRole.None;
        delete issuerDocHash[issuer];

        emit IssuerRoleSet(issuer, IssuerRole.None);
        emit RoleRevoked(issuer);
    }

    /**
    *
    * 
    */
    function registeredVehicle(
        string calldata vin, 
        address initialOwner, 
        uint256 initialMileage
    ) external onlyIssuer(IssuerRole.Dealer) {
        bytes32 vinHash = keccak256(abi.encodePacked(vin));
        require(!vehicles[vinHash].exists, "This vehicle has already been registered !");

        vehicles[vinHash] = Vehicle({ exists: true, currentOwner: initialOwner, lastMileage: initialMileage });
        ownershipHistory[vinHash].push(initialOwner);

        emit VehicleRegistered(vinHash, initialOwner, initialMileage);
    }

    function addServiceRecord(
        bytes32 vinHash,
        uint256 mileage,
        string calldata description
    ) external onlyIssuer(IssuerRole.Workshop) {
        require(vehicles[vinHash].exists, "Vehicle not found !");
        require(mileage >= vehicles[vinHash].lastMileage, "The mileage cannot be lower than the last recorded entry.");

        vehicles[vinHash].lastMileage = mileage;
        serviceHistory[vinHash].push(ServiceRecord({
            timestamp: block.timestamp,
            mileage: mileage,
            description: description,
            issuer: msg.sender
        }));

        emit ServiceAdded(vinHash, mileage, msg.sender);
    }

    function mileageCorrection(
        bytes32 vinHash,
        uint256 newMileage,
        string calldata reason
    ) external onlyIssuer(IssuerRole.Dealer) {
        require(vehicles[vinHash].exists, "Vehicle not found !");
        vehicles[vinHash].lastMileage = newMileage;

        emit MileageCorrected(vinHash, newMileage, reason, msg.sender);
    }

    function addIncidentRecords(
        bytes32 vinHash, 
        string calldata incidentType, 
        string calldata description
    ) external onlyIssuer(IssuerRole.Insurance) {
        require(vehicles[vinHash].exists, "Vehicle not found !");
        incidentHistory[vinHash].push(IncidentRecord({
            timestamp: block.timestamp,
            incidentType: incidentType,
            description: description,
            issuer: msg.sender
        }));

        emit IncidentAdded(vinHash, incidentType, msg.sender);
    }

    function transferOwnership(
        bytes32 vinHash,
        address newOwner
    ) external {
        require(vehicles[vinHash].exists, "Vehicle not found !");
        require(msg.sender == vehicles[vinHash].currentOwner, "You're not the owner of this vehicle.");

        address previousOwner = vehicles[vinHash].currentOwner;
        vehicles[vinHash].currentOwner = newOwner;
        ownershipHistory[vinHash].push(newOwner);

        emit OwnershipTransferred(vinHash, previousOwner, newOwner);
    }

    function getVehicleSummary(bytes32 vinHash) 
        external 
        view
        returns (address currentOwner, uint256 lastMileage, uint256 totalServices, uint256 totalIncidents, uint256 totalOwners)
    {
        Vehicle memory vehicle = vehicles[vinHash];
        return (
            vehicle.currentOwner,
            vehicle.lastMileage,
            serviceHistory[vinHash].length,
            incidentHistory[vinHash].length,
            ownershipHistory[vinHash].length
        );
    }

    function hashVin(string calldata vin) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(vin));
    }

}
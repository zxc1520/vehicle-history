// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";

contract VehicleHistory is Ownable {

    enum IssuerRole { None, Garage, Insurance, Dealer, Notary }
    
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

    event IssuerRoleSet(address indexed issuer, IssuerRole role);
    event VehicleRegistered(bytes32 indexed vinHash, address indexed initialOwner, uint256 initialMileage);
    event ServiceAdded(bytes32 indexed vinHash, uint256 mileage, address indexed issuer);
    event IncidentAdded(bytes32 indexed vinHash, string incidentType, address indexed issuer);
    event MileageCorrected(bytes32 indexed vinHash, uint256 newMileage, string reason, address indexed correctedBy);
    event OwnershipTransferred(bytes32 indexed vinHash, address indexed from, address indexed to);

    constructor() Ownable(msg.sender) {}

    modifier onlyIssuer(IssuerRole role) {
        require(authorizedIssuers[msg.sender] == role, "This Address is not authorized to perform this action !");
        _;
    }

    function setIssuerRole(address issuer, IssuerRole role) external onlyOwner {
        authorizedIssuers[issuer] = role;
        emit IssuerRoleSet(issuer, role);
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
    ) external onlyIssuer(IssuerRole.Garage) {
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
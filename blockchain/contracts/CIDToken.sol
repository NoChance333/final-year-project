// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "../openzeppelin/contracts/access/Ownable.sol";

/**
 * @title CIDToken
 * @dev ERC-721 token representing tokenized assets with IPFS CID metadata.
 */
contract CIDToken is ERC721URIStorage, Ownable {
    uint256 private _tokenIdCounter;

    event TokenMinted(address indexed recipient, uint256 indexed tokenId, string metadataCID);

    constructor() ERC721("NovisAssetToken", "NOVIS") {
        _tokenIdCounter = 0;
    }

    /**
     * @notice Mint a new ERC-721 token directly to recipient with an IPFS CID
     * @param recipient The wallet address receiving the token (e.g., user's MetaMask wallet)
     * @param metadataCID The IPFS CID of the uploaded document/asset
     * @return The newly minted tokenId
     */
    function mintToken(address recipient, string memory metadataCID) public onlyOwner returns (uint256) {
        require(recipient != address(0), "Invalid recipient address");
        _tokenIdCounter++;
        uint256 newTokenId = _tokenIdCounter;

        _safeMint(recipient, newTokenId);
        _setTokenURI(newTokenId, metadataCID);

        emit TokenMinted(recipient, newTokenId, metadataCID);
        return newTokenId;
    }

    /**
     * @notice Get current total minted tokens count
     */
    function totalMinted() public view returns (uint256) {
        return _tokenIdCounter;
    }
}

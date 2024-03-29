# Ethernaut Solutions
## Introduction
This repository contains all the solution I used to complete the Ethernaut challenges.

:warning: Please do not copy/paste this content to complete Ethernaut challenges. Take time to understand the challenges! :warning:

## Hello Ethernaut
First deploy the contract by clicking "Get new instance".
Then, look at the contract.abi to get smart contract functions.
Call the password() view function, and pass the returned result as parameter to the authenticate() function.

## Fallback
By reading the code, we can identify that the receive() function should be called to get contract ownership. But we need to contribute before calling the receive function (or the call will fail).

So, we need to :
 1. call contribute with less than 0.001 ether as value
 2. call the receive function (by sending some ether)
 3. call the withdraw function

## Fallout
The function Fal1out allow the sender to become the owner of the contract. It is a typographical error, and the comment let us think that it is the constructor function.
But since Solidity v0.5.0, the "constructor" function is used instead of the name of the contract.

## Coin Flip
This coin flip smart contract needs to use a random value. To do so, it uses the block value to calculate a number. As the block value is well known, the calculated number can be predicted and automatically calculated by another smart contract.


## Telephone
The contract require that tx.origin != msg.sender to change owner. This can be easily done using a smart contract to call this function.

## Token
The token contract is vulnerable to an integer underflow. If we have 20 tokens, we can ask to send 21 tokens. Our balance would be -1 if it was a signed integer. As it is unsigned, -1 corresponds to the larger number allowed by the uint256 format.

## Delegation
The objective is to gain ownership of the Delegation contract. To do so, we can exploit the delegatecall. The official Solidity documentation says : 
```
"There exists a special variant of a message call, named delegatecall which is identical to a message call apart from the fact that the code at the target address is executed in the context (i.e. at the address) of the calling contract and msg.sender and msg.value do not change their values."
```
So we can call the pwn function from Delegate contract, but in the context of the Delegation contract. This allows us to take ownership of the contract.


## Force
The goal is to make the balance of the contract greater than zero. To do so, we will use the selfdestruct of another contract to make the balance non-zero.


## Vault
Even if a variable is private, all the datas are public in Ethereum. So we can read the private password and unlock the contract.

## King
This contract does send the prize to the king of the contract. If the king is a smart contract that revert when it receives funds, the king will never change.

## Re-entrancy
On this contract, the vulnerability is that the withdraw function does send the funds before getting the balance updated. Using an attacker smart contract, a re-entrancy attack is possible.


## Elevator
Here, the objective is to set the top variable to true. To do so, it calls the msg.sender to know if top is true or false. We have to develop a smart contract with a isLastFloor() function that returns false during the first call, then true to the second call.

## Privacy
The objective is to unlock the contract. We need to know the key to do this.
Reading the storage of the smart contract will be done using web3.eth.getStorageAt(). We need to deeply understand how smart contracts store data to find the result.
Here is a picture that explains what data should be read :

![Privacy contract storage](images/Privacy.png)

## Gatekeeper One
Here, we do need to:
- use a contract to get msg.sender != tx.origin
- cast the tx.origin to different type to complete all checks: To do so, we identify that uint32(num) == uint16(num) != uint64(num) == uint16(uint160(tx.origin))
- find the right amount of gas: we just have to brute force to find the right amount of gas, so check `gasleft() % 8191 == 0` will pass.

## Gatekeeper Two

TODO

## Naught Coin
This contract locks the transfer function for 10 years. But it is possible to use the approve() and transferFrom() to transfer funds.



## Preservation
We are going to exploit delegatecall(). First, we can see that the LibraryContract does modify the first storage slot, which is the address of the library in the context of the vulnerable contract. So, we are able to modify this address to set it to an attacker contract. Our attacker contract will modify the third slot, to modify the owner address.


## Recovery

This one is pretty simple. Go to the blockchain explorer (like Etherscan) and go to the Recovery contract. In the internal functions, you should see a contract creation (which is the Token contract). Take the address, and call the destroy function with your address as parameter.


## Magic Number
Our smart contract just needs to return the value `42`. It needs to be as small as possible.

To deploy a smart contract, there are two main byte codes used:
  - The init code: It is executed during the creation to load the runtime code, and do other things if needed. Constructor parameters are used here.
  - The runtime code: The executed code on every contract calls.


## Alien Codex

## Denial
As we can set any withdraw partner, we can create a contract that will be a partner and receive 1% of the contract ether balance. We just have to create an infinite loop in the receive function. And so, ether will be locked in contract for ever!

## Shop
Here the vulnerable contract calls the Buyer 2 times. It is simple. For first call, the price() function returned value will be 100, the second time it will be < 100.

## Dex
TODO


## Dex Two
Looking at the swap function, we can see that the function does not verify that `from` is token1 or token2. So, we can create our own ERC20 Token to manipulate the Dex.

## Puzzle Wallet
Here, we can see in multicall that we are able to call deposit two times. This will increase our balance in contract, and we will be able to drain funds that we didn't deposit.

## Motorbike
Here, our goal is to selfdestruct the engine of the motorbike. The motorbike contract uses delegatecall, and has called the `initialize()` function of the implementation in constructor. But, the implementation has not been initialized. So, as an attacker, we can initialize the implementation and upgrade it to an attacker contract. Then, as it delegatecalls, we are able to selfdestruct the contract.


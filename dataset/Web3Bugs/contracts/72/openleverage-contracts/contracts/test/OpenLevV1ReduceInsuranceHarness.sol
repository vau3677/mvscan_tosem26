// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.7.6;

import "../OpenLevV1.sol";

contract OpenLevV1ReduceInsuranceHarness is OpenLevV1 {
    function setPoolInsurance(uint16 marketId, uint pool0Insurance, uint pool1Insurance) external {
        markets[marketId].pool0Insurance = pool0Insurance;
        markets[marketId].pool1Insurance = pool1Insurance;
    }

    function setTotalHeld(address token, uint amount) external {
        totalHelds[token] = amount;
    }

    function exposedReduceInsurance(
        uint totalRepayment,
        uint remaining,
        uint16 marketId,
        bool longToken,
        address token,
        uint reserve
    ) external returns (uint) {
        return reduceInsurance(totalRepayment, remaining, marketId, longToken, token, reserve);
    }
}

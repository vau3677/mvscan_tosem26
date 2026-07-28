const OpenLevV1Lib = artifacts.require("OpenLevV1Lib");
const Harness = artifacts.require("OpenLevV1ReduceInsuranceHarness");

contract("OpenLevV1 reduceInsurance PoC", accounts => {
    const token = accounts[8];
    const marketId = 0;
    const totalHeld = web3.utils.toBN("1000");
    const reserve = web3.utils.toBN("1000");
    const insurance = web3.utils.toBN("100");
    const totalRepayment = web3.utils.toBN("1010");
    const remaining = web3.utils.toBN("960");
    const neededShares = totalRepayment.sub(remaining);

    let harness;

    beforeEach(async () => {
        const lib = await OpenLevV1Lib.new();
        await Harness.link("OpenLevV1Lib", lib.address);
        harness = await Harness.new();
    });

    it("pool0 insurance branch keeps totalHelds synchronized", async () => {
        await harness.setPoolInsurance(marketId, insurance, 0);
        await harness.setTotalHeld(token, totalHeld);

        await harness.exposedReduceInsurance(
            totalRepayment,
            remaining,
            marketId,
            true,
            token,
            reserve
        );

        const market = await harness.markets(marketId);
        const totalHeldAfter = await harness.totalHelds(token);

        assert.equal(market.pool0Insurance.toString(), insurance.sub(neededShares).toString());
        assert.equal(totalHeldAfter.toString(), totalHeld.sub(neededShares).toString());
    });

    it("PoC: pool1 insurance branch consumes insurance but leaves totalHelds stale", async () => {
        await harness.setPoolInsurance(marketId, 0, insurance);
        await harness.setTotalHeld(token, totalHeld);

        await harness.exposedReduceInsurance(
            totalRepayment,
            remaining,
            marketId,
            false,
            token,
            reserve
        );

        const market = await harness.markets(marketId);
        const totalHeldAfter = await harness.totalHelds(token);

        assert.equal(market.pool1Insurance.toString(), insurance.sub(neededShares).toString());

        // This should match the pool0 branch and be totalHeld - neededShares.
        // On the vulnerable code it remains unchanged, leaving the share denominator inflated.
        assert.equal(totalHeldAfter.toString(), totalHeld.toString());
        assert.notEqual(totalHeldAfter.toString(), totalHeld.sub(neededShares).toString());
    });
});

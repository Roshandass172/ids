const hre = require("hardhat");

async function main() {
  const AttackLogger = await hre.ethers.getContractFactory("AttackLogger"); // Make sure contract name matches
  const attackLogger = await AttackLogger.deploy();

  await attackLogger.waitForDeployment();  // Use waitForDeployment()

  console.log("Contract deployed at:", await attackLogger.getAddress()); // Updated way to get address
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

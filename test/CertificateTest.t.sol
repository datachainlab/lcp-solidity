// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.12;

import "../contracts/AVRValidator.sol";
import "./TestHelper.t.sol";

contract CertificateTest is BasicTest {
    function setUp() public {}

    function testIASCertVerification() public {
        vm.warp(2524607999);
        AVRValidator.RSAParams memory rootParams =
            AVRValidator.verifyRootCACert(vm.readFileBinary("./test/data/certs/Intel_SGX_Attestation_RootCA.der"));
        assertEq(
            rootParams.modulus,
            hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B"
        );
        assertEq(rootParams.exponent, hex"010001");
        assertEq(rootParams.notAfter, 2524607999);

        vm.warp(2524607999 + 1);
        vm.expectRevert();
        AVRValidator.verifyRootCACert(vm.readFileBinary("./test/data/certs/Intel_SGX_Attestation_RootCA.der"));

        vm.warp(1795167418);
        AVRValidator.RSAParams memory signingParams = AVRValidator.verifySigningCert(
            rootParams.modulus, rootParams.exponent, vm.readFileBinary("./test/data/certs/intel_signing.der")
        );
        assertEq(
            signingParams.modulus,
            hex"A97A2DE0E66EA6147C9EE745AC0162686C7192099AFC4B3F040FAD6DE093511D74E802F510D716038157DCAF84F4104BD3FED7E6B8F99C8817FD1FF5B9B864296C3D81FA8F1B729E02D21D72FFEE4CED725EFE74BEA68FBC4D4244286FCDD4BF64406A439A15BCB4CF67754489C423972B4A80DF5C2E7C5BC2DBAF2D42BB7B244F7C95BF92C75D3B33FC5410678A89589D1083DA3ACC459F2704CD99598C275E7C1878E00757E5BDB4E840226C11C0A17FF79C80B15C1DDB5AF21CC2417061FBD2A2DA819ED3B72B7EFAA3BFEBE2805C9B8AC19AA346512D484CFC81941E15F55881CC127E8F7AA12300CD5AFB5742FA1D20CB467A5BEB1C666CF76A368978B5"
        );
        assertEq(signingParams.exponent, hex"010001");
        assertEq(signingParams.notAfter, 1795167418);

        vm.warp(1795167418 + 1);
        vm.expectRevert();
        AVRValidator.verifySigningCert(
            rootParams.modulus, rootParams.exponent, vm.readFileBinary("./test/data/certs/intel_signing.der")
        );
    }

    function testSimulationCertVerification() public {
        vm.warp(2550130947);
        AVRValidator.RSAParams memory rootParams =
            AVRValidator.verifyRootCACert(vm.readFileBinary("./test/data/certs/simulation_rootca.der"));
        assertEq(
            rootParams.modulus,
            hex"DB703C5FFD6E95A565825D643EFCDA4DC65EE805CDE9428043908CEBCD72ED0E407DEC627A9E1492F7CB57C0EE9F18BA734130F445841A41D3AA258E77478013624F3D4CFA2A21EF13FF26EAD1B2FF075A11C6FDF75DA49C3B68882FC91B59A385A7A71ECC2E187201461544983DA351F8CB782964E0FFCA82556272E395BA75ACC3EF72319B5754C4A0845A1A76614DB24E44CFF8C9E1521779DCE6A311B24B78FE52506DA5EC5EB603E2A9DD2CAD7CF44C05CAFF8F7E36577DE001602FAFC5473EAC96EEE977EC04F8D597564715A2C3C085B023DDF773E0859E737816EFC96F9B2207DA33D3BA6ACC5FBB235FD21AF28CDE704F98F923AC0604B960DF05D3374CEF7DCF676FF72BD2CB6A8A932AF367EC87E23AA47BD09FBA3A65F0D1266E6651559308E398B6EF427CFF1301B71F323B4DD46696E70EF6981F442F86A69FA763842727D4E19FB30EE683530F6E3E9F506F1E60C74BC747D14F2D9DF4DE0633037B80263AD8A36DACE08907B8FCE56B4BD295168CD37D403E14D32AF04645"
        );
        assertEq(rootParams.exponent, hex"010001");
        assertEq(rootParams.notAfter, 2550130947);
        vm.warp(2550130947 + 1);
        vm.expectRevert();
        AVRValidator.verifyRootCACert(vm.readFileBinary("./test/data/certs/simulation_rootca.der"));

        vm.warp(2550130947);
        AVRValidator.RSAParams memory signingParams = AVRValidator.verifySigningCert(
            rootParams.modulus, rootParams.exponent, vm.readFileBinary("./test/data/certs/simulation_signing.der")
        );
        assertEq(
            signingParams.modulus,
            hex"90D30A012CC4A8F9A1FFF7F3D103D9733F3CD390E9481A99E995B47428814C5CE9DCD814D37C2C0B6DF082A551F4B0167C355B68F88E38B870F7D341422CC7717C2E2A0034D884A9532BBB6D0C0584729633B611BF5E2E29C5ED76B6A564E2FAB8FA3944765709392C9714B2DBDAFF0B283ADF3C6ABD3663B8FA5DE345B54ADDBFC07F02D7F3975BFBA01B7CB86D9304D35AA41E3D672502E361ABFCA07847F770AEE2F9E24B464089F55AFA5F411D18FE8F2ED7F2539315B5144A35E02FAACDD86403E43B6CA397D3C23DAE91599862E99F8DCB6F163D4A27573FDD5C7DDBDD5DF1D98140DC4567E7A579E18E3D92A982B2848FBF56193135A07A80A7104F6F"
        );
        assertEq(signingParams.exponent, hex"010001");
        assertEq(signingParams.notAfter, 2550130947);
        vm.warp(2550130947 + 1);
        vm.expectRevert();
        AVRValidator.verifySigningCert(
            rootParams.modulus, rootParams.exponent, vm.readFileBinary("./test/data/certs/simulation_signing.der")
        );
    }

    string internal constant testCertsBaseDir = "./test/.tmp/testcerts";
    string internal constant genCertCmd = "./scripts/gencert.sh";

    struct RSAParamsCase {
        string bits;
        string exponent;
    }

    function testValidSigningCerts() public {
        string memory testCertsDir = string(abi.encodePacked(testCertsBaseDir, "/", "valid_signing_certs"));
        RSAParamsCase[4] memory cases = [
            RSAParamsCase("2048", "65537"),
            RSAParamsCase("2048", "3"),
            RSAParamsCase("4096", "65537"),
            RSAParamsCase("4096", "3")
        ];
        vm.warp(1795167418);
        cleanupTestCerts(testCertsDir);
        genRsaRootCert(testCertsDir);
        for (uint256 i = 0; i < cases.length; i++) {
            genRsaSigningCert(testCertsDir, cases[i].bits, cases[i].exponent);
            AVRValidator.RSAParams memory rootParams = AVRValidator.verifyRootCACert(
                vm.readFileBinary(string(abi.encodePacked(testCertsDir, "/root.crt.der")))
            );
            AVRValidator.verifySigningCert(
                rootParams.modulus,
                rootParams.exponent,
                vm.readFileBinary(string(abi.encodePacked(testCertsDir, "/signing.crt.der")))
            );
        }
    }

    function testInvalidRootCerts() public {
        string memory testCertsDir = string(abi.encodePacked(testCertsBaseDir, "/", "invalid_root_certs"));
        vm.warp(1795167418);
        cleanupTestCerts(testCertsDir);
        genEcdsaRootCert(testCertsDir);

        vm.expectRevert();
        AVRValidator.verifyRootCACert(vm.readFileBinary(string(abi.encodePacked(testCertsDir, "/root.crt.der"))));
    }

    function testInvalidSigningCerts() public {
        string memory testCertsDir = string(abi.encodePacked(testCertsBaseDir, "/", "invalid_signing_certs"));
        vm.warp(1795167418);
        cleanupTestCerts(testCertsDir);
        genRsaRootCert(testCertsDir);
        genEcdsaSigningCert(testCertsDir);

        AVRValidator.RSAParams memory rootParams =
            AVRValidator.verifyRootCACert(vm.readFileBinary(string(abi.encodePacked(testCertsDir, "/root.crt.der"))));
        vm.expectRevert();
        AVRValidator.verifySigningCert(
            rootParams.modulus,
            rootParams.exponent,
            vm.readFileBinary(string(abi.encodePacked(testCertsDir, "/signing.crt.der")))
        );
    }

    function cleanupTestCerts(string memory testCertsDir) internal {
        string[] memory cmd = new string[](3);
        cmd[0] = "rm";
        cmd[1] = "-rf";
        cmd[2] = testCertsDir;
        runCmd(cmd);
    }

    function genRsaRootCert(string memory testCertsDir) internal {
        string[] memory cmd = new string[](3);
        cmd[0] = genCertCmd;
        cmd[1] = testCertsDir;
        cmd[2] = "gen_rsa_root_cert";
        runCmd(cmd);
    }

    function genRsaSigningCert(string memory testCertsDir, string memory bits, string memory exponent) internal {
        string[] memory cmd = new string[](5);
        cmd[0] = genCertCmd;
        cmd[1] = testCertsDir;
        cmd[2] = "gen_rsa_signing_cert";
        cmd[3] = bits;
        cmd[4] = exponent;
        runCmd(cmd);
    }

    function genEcdsaRootCert(string memory testCertsDir) internal {
        string[] memory cmd = new string[](3);
        cmd[0] = genCertCmd;
        cmd[1] = testCertsDir;
        cmd[2] = "gen_ecdsa_root_cert";
        runCmd(cmd);
    }

    function genEcdsaSigningCert(string memory testCertsDir) internal {
        string[] memory cmd = new string[](3);
        cmd[0] = genCertCmd;
        cmd[1] = testCertsDir;
        cmd[2] = "gen_ecdsa_signing_cert";
        runCmd(cmd);
    }

    function runCmd(string[] memory cmd) internal {
        Vm.FfiResult memory f = vm.tryFfi(cmd);
        string memory cmdStr;
        for (uint256 i = 0; i < cmd.length; i++) {
            cmdStr = string(abi.encodePacked(cmdStr, cmd[i], " "));
        }
        require(f.exitCode == 0, string(abi.encodePacked("Failed to run command: ", cmdStr, " err: ", f.stderr)));
    }
}

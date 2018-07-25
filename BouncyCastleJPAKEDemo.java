/*  
 * @author: haofeng66@gmail.com
 * 
 * 28 March 2013
 * 
 * This is a code example to show how to use J-PAKE in BouncyCastle.
 * (After I wrote this example, I learned that Bouncycastle had
 * acutally already included a J-PAKE code example written by Phil Clay.
 * See: http://www.bouncycastle.org/viewcvs/viewcvs.cgi/java/crypto/src/org/bouncycastle/crypto/examples/JPAKEExample.java?revision=1.1&view=markup
 * The two examples happen to be almost identical.)
 *
 * prerequisite: BouncyCastle version 1.48 and above.
 * Jar file used in this example: bcprov-ext-jdk15on-148.jar
 * 
 * The example is based on 1) a native Java implementation of J-PAKE, and
 * 2) unit tests of J-PAKE in BouncyCastle). See below:
 * 
 * 1). http://homepages.cs.ncl.ac.uk/feng.hao/files/JPAKEDemo.java
 * 2). http://www.bouncycastle.org/viewcvs/viewcvs.cgi/java/crypto/test/src/org/bouncycastle/crypto/agreement/test/JPAKEParticipantTest.java?view=markup
 */

import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroup;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroups;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;

public class BouncyCastleJPAKEDemo {
	
	JPAKEPrimeOrderGroup group = JPAKEPrimeOrderGroups.NIST_2048;
	BigInteger p = group.getP();
	BigInteger q = group.getQ();
	BigInteger g = group.getG();
	
	/* Shared passwords for Alice and Bob 
	 * Try changing them to different values? 
	 */	
	String s1Str = "deadbeef";
	String s2Str = "deadbeef";

	/* SignerIDs for Alice and Bob. Obviously, they must be different. 
	 * In practical implementation, it is worth checking that explicitly.
	 */
	String aliceID = "Alice";
	String bobID = "Bob";
	
	public static void main(String[] args) {

		BouncyCastleJPAKEDemo test = new BouncyCastleJPAKEDemo();
		test.run();		
	}
	
	private void run () {
		
		System.out.println("Public parameters for the cyclic group:");
		System.out.println("p ("+p.bitLength()+" bits): " + p.toString(16));
		System.out.println("q ("+q.bitLength()+" bits): " + q.toString(16));
		System.out.println("g ("+p.bitLength()+" bits): " + g.toString(16));
		System.out.println("p mod q = " + p.mod(q).toString(16));
		System.out.println("g^{q} mod p = " + g.modPow(q,p).toString(16));
		System.out.println("");
    		
		System.out.println("(Secret passwords used by Alice and Bob: "+
				"\""+s1Str+"\" and \""+s2Str+"\")\n");
    	
		JPAKEParticipant alice = new JPAKEParticipant(aliceID, s1Str.toCharArray(), group);
		JPAKEParticipant bob = new JPAKEParticipant(bobID, s2Str.toCharArray(), group);
    	
		/* Step 1: Alice sends g^{x1}, g^{x2}, and Bob sends g^{x3}, g^{x4} */
		JPAKERound1Payload aliceRound1 = alice.createRound1PayloadToSend();
		JPAKERound1Payload bobRound1 = bob.createRound1PayloadToSend();
    	
		System.out.println("************Step 1**************");
		System.out.println("Alice sends to Bob: ");
		System.out.println("g^{x1}="+aliceRound1.getGx1().toString(16));
		System.out.println("g^{x2}="+aliceRound1.getGx2().toString(16));
		/* The ZKP is a two element array, containing {g^v, r} */ 
		System.out.println("KP{x1}={"+aliceRound1.getKnowledgeProofForX1()[0].toString(16)+
				"};{"+aliceRound1.getKnowledgeProofForX1()[1].toString(16)+"}");
		System.out.println("KP{x2}={"+aliceRound1.getKnowledgeProofForX2()[0].toString(16)+
				"};{"+aliceRound1.getKnowledgeProofForX2()[1].toString(16)+"}");
		System.out.println("");

		System.out.println("Bob sends to Alice: ");
		System.out.println("g^{x3}="+bobRound1.getGx1().toString(16));
		System.out.println("g^{x4}="+bobRound1.getGx2().toString(16));
		/* The ZKP is a two element array, containing {g^v, r} */ 
		System.out.println("KP{x3}={"+bobRound1.getKnowledgeProofForX1()[0].toString(16)+
				"};{"+bobRound1.getKnowledgeProofForX1()[1].toString(16)+"}");
		System.out.println("KP{x4}={"+bobRound1.getKnowledgeProofForX2()[0].toString(16)+
				"};{"+bobRound1.getKnowledgeProofForX2()[1].toString(16)+"}");
		System.out.println("");
    	
		/* Alice verifies Bob's ZKPs and also check g^{x4} != 1*/
		try {
			alice.validateRound1PayloadReceived(bobRound1);    		
		}catch (CryptoException e){
			e.printStackTrace();
			System.out.println("Invalid round 1 payload received. Exit.");
			System.exit(0);
		}
		System.out.println("Alice checks Bob's round 1 payload: OK");
    
		/* Similarly, Bob verifies Alice's round 1 payload */
		try {
			bob.validateRound1PayloadReceived(aliceRound1);    		
		}catch (CryptoException e){
			e.printStackTrace();
			System.out.println("Invalid round 1 payload received. Exit.");
			System.exit(0);
		}
		System.out.println("Bob checks Alice's round 1 payload: OK");
    	
		/* Step 2: Alice sends A and Bob sends B */
		JPAKERound2Payload aliceRound2 = alice.createRound2PayloadToSend();
		JPAKERound2Payload bobRound2 = bob.createRound2PayloadToSend();
    
		System.out.println("\n************Step 2**************");
		System.out.println("Alice sends to Bob: ");
		System.out.println("A="+aliceRound2.getA().toString(16));
		System.out.println("KP{x2*s}={"+aliceRound2.getKnowledgeProofForX2s()[0].toString(16)+
				"},{"+aliceRound2.getKnowledgeProofForX2s()[1].toString(16)+"}");
		System.out.println("");

		System.out.println("Bob sends to Alice: ");
		System.out.println("B="+bobRound2.getA().toString(16));
		System.out.println("KP{x4*s}={"+bobRound2.getKnowledgeProofForX2s()[0].toString(16)+
				"},{"+bobRound2.getKnowledgeProofForX2s()[1].toString(16)+"}");
		System.out.println("");
    	
		/* Alice verifies Bob's ZKP in step 2*/
		try {
			alice.validateRound2PayloadReceived(bobRound2);    		
		}catch (CryptoException e){
			e.printStackTrace();
			System.out.println("Invalid round 2 payload received. Exit.");
			System.exit(0);
		}
		System.out.println("Alice checks Bob's round 1 payload: OK");
    	
		/* Similarly, Bob verifies Alice's ZKP in step 2*/
		try {
			bob.validateRound2PayloadReceived(aliceRound2);    		
		}catch (CryptoException e){
			e.printStackTrace();
			System.out.println("Invalid round 2 payload received. Exit.");
			System.exit(0);
		}
		System.out.println("Bob checks Alice's round 2 payload: OK");
    	
		/* After step 2, compute the common key material */
		BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
		BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();
    	
		System.out.println("\n************After step 2**************");
		System.out.println("Alice's raw key material \t K="+aliceKeyingMaterial.toString(16));
		System.out.println("Bob's raw key material \t K="+aliceKeyingMaterial.toString(16));    	
    	
		/* Step 3 (optional): Explicit key confirmation */
		JPAKERound3Payload aliceRound3 = alice.createRound3PayloadToSend(aliceKeyingMaterial);
		JPAKERound3Payload bobRound3 = bob.createRound3PayloadToSend(bobKeyingMaterial);
    
		System.out.println("\n************ Explicit key confirmation (optional) ***********");
    	
		/* The key confirmation in the Bouncycastle implementation uses a method from NIST SP 800-56A; 
		 * it has the advantage of preserving the symmetry of the implementation. Alternatively, one could 
		 * use the SPEKE method: Alice sends a hash of the hash of the key and Bob replies with a hash of the 
		 * key, however the method is not symmetric.
		 */
    	
		/* Alice performs key confirmation */
		try {
			alice.validateRound3PayloadReceived(bobRound3, aliceKeyingMaterial);
		}catch(CryptoException e){
			e.printStackTrace();
			System.out.println("Key confirmation failed. Exit.");
			System.exit(0);
		}
		System.out.println("Alice performs key confirmation: OK");
    	
		/* Similarly, Bob performs key confirmation */
		try {
			bob.validateRound3PayloadReceived(aliceRound3, bobKeyingMaterial);
		}catch(CryptoException e){
			e.printStackTrace();
			System.out.println("Key confirmation failed. Exit.");
			System.exit(0);
		}
		System.out.println("Bob performs key confirmation: OK");
    	    	
		/* Finally Alice and Bob can start secure communication: 
		 * using a session key to protect confidentiality and integrity */
    
		System.out.println("\n************ Secure communication (ommited) ***********");
    	
		/* The choice of KDF is left to the developer. As an example, we use SHA-256 here. */
		System.out.println("Alice uses a session key \t K="+getSHA256(aliceKeyingMaterial).toString(16));
		System.out.println("Bob uses a session key \t K="+getSHA256(bobKeyingMaterial).toString(16));    	
	}

	public BigInteger getSHA256(BigInteger K) {

		java.security.MessageDigest sha = null;

		try {
			sha = java.security.MessageDigest.getInstance("SHA-256");
			sha.update(K.toByteArray());
		} catch (Exception e) {
			e.printStackTrace();
		}

		return new BigInteger(1, sha.digest()); // 1 for positive int
	}
	
}

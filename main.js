var _hash = {
	init: SHA256_init,
	update: SHA256_write,
	getBytes: SHA256_finalize
};

function simpleHash(message) {
	_hash.init();
	_hash.update(message);
	return _hash.getBytes();
}
let getAccountId = function(secretPhrase) {
	return getAccountIdFromPublicKey(getPublicKey(converters.stringToHexString(secretPhrase)));
};

let getPublicKey = function(secretPhrase, ) {
    var secretPhraseBytes = converters.hexStringToByteArray(secretPhrase); //
    var digest = simpleHash(secretPhraseBytes);  //
    return converters.byteArrayToHexString(curve25519.keygen(digest).p); //
};
function byteArrayToBigInteger(byteArray, startIndex) {
	var value = new BigInteger("0", 10);
	var temp1, temp2;
	for (var i = byteArray.length - 1; i >= 0; i--) {
	    temp1 = value.multiply(new BigInteger("256", 10));
	    temp2 = temp1.add(new BigInteger(byteArray[i].toString(10), 10));
	    value = temp2;
    }
    return value;
}
 
let getAccountIdFromPublicKey = function(publicKey, RSFormat) {
	var hex = converters.hexStringToByteArray(publicKey);

	_hash.init();
	_hash.update(hex);

	var account = _hash.getBytes();

	account = converters.byteArrayToHexString(account);

	var slice = (converters.hexStringToByteArray(account)).slice(0, 8);

	var accountId = byteArrayToBigInteger(slice).toString();
 
    return accountId;
};
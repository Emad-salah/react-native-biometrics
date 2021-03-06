declare module "react-native-biometrics" {
	/**
	 * Enum for touch id sensor type
	 */
	const TouchID: string;
	/**
	 * Enum for face id sensor type
	 */
	const FaceID: string;
	/**
	 * Returns promise that resolves to null, TouchID, or FaceID
	 * @returns {Promise} Promise that resolves to null, TouchID, or FaceID
	 */
	function getSensorAvailability(): Promise<{
		hardwareExists: boolean;
		fingerprintsEnrolled: boolean;
		sensorAvailable: boolean;
	}>;
	/**
	 * Sets a biometric key alias. This is useful for creating
	 * multiple users in one app with different key pairs
	 * @returns {string} The newly set alias
	 */
	function setBiometricKeyAlias(): string;
	/**
	 * Gets the biometric key alias. This is useful for creating
	 * multiple users in one app with different key pairs
	 * @returns {string} The current alias
	 */
	function getBiometricKeyAlias(): string;
	/**
	 * Prompts user with biometrics dialog using the passed in prompt message if
	 * it is provided, returns promise that resolves to the public key of the
	 * newly generated key pair
	 * @param {string} promptMessage
	 * @returns {Promise}  Promise that resolves to newly generated public key
	 */
	function createKeys(promptMessage?: string): Promise<string>;
	/**
	 * Returns promise that resolves to true or false indicating if the keys
	 * were properly deleted
	 * @returns {Promise} Promise that resolves to true or false
	 */
	function deleteKeys(): Promise<boolean>;
	/**
	 * Prompts user with biometrics dialog using the passed in prompt message and
	 * returns promise that resolves to a cryptographic signature of the payload
	 * @param {string} promptMessage
	 * @param {string} payload
	 * @returns {Promise}  Promise that resolves to cryptographic signature
	 */
	function createSignature(
		promptMessage: string,
		payload: string
	): Promise<string>;
	/**
	 * Prompts user with biometrics dialog using the passed in prompt message and
	 * returns promise that resolves if the user passes, and
	 * rejects if the user fails or cancels
	 * @param {string} promptMessage
	 * @returns {Promise}  Promise that resolves if the user passes, and
	 * rejects if the user fails or cancels
	 */
	function simplePrompt(promptMessage: string): Promise<boolean>;
}

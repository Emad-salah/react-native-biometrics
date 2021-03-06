import { NativeModules, Platform } from "react-native";

const { ReactNativeBiometrics } = NativeModules;

export default {
	/**
	 * Enum for touch id sensor type
	 */
	TouchID: "TouchID",
	/**
	 * Enum for face id sensor type
	 */
	FaceID: "FaceID",
	/**
	 * Returns promise that resolves to null, TouchID, or FaceID
	 * @returns {Promise} Promise that resolves to null, TouchID, or FaceID
	 */
	getSensorAvailability: async () => {
		const sensorAvailable = ReactNativeBiometrics.isSensorAvailable();
		if (Platform.OS === "ios") {
			const sensorExists = sensorAvailable !== "None";
			return {
				hardwareExists: sensorExists,
				fingerprintsEnrolled: sensorExists,
				sensorAvailable: sensorExists
			};
		}

		if (!sensorAvailable) {
			return {
				hardwareExists: false,
				fingerprintsEnrolled: false,
				sensorAvailable: false
			};
		}

		return sensorAvailable;
	},
	/**
	 * Sets a biometric key alias. This is useful for creating
	 * multiple users in one app with different key pairs
	 * @param {string} alias
	 * @returns {string} The newly set alias
	 */
	setBiometricKeyAlias: alias => {
		return ReactNativeBiometrics.setBiometricKeyAlias(alias);
	},
	/**
	 * Gets the biometric key alias. This is useful for creating
	 * multiple users in one app with different key pairs
	 * @returns {string} The newly set alias
	 */
	getBiometricKeyAlias: () => {
		return ReactNativeBiometrics.getBiometricKeyAlias();
	},
	/**
	 * Prompts user with biometrics dialog using the passed in prompt message if
	 * it is provided, returns promise that resolves to the public key of the
	 * newly generated key pair
	 * @param {string} promptMessage
	 * @returns {Promise}  Promise that resolves to newly generated public key
	 */
	createKeys: promptMessage => {
		return ReactNativeBiometrics.createKeys(promptMessage);
	},
	/**
	 * Returns promise that resolves to true or false indicating if the keys
	 * were properly deleted
	 * @returns {Promise} Promise that resolves to true or false
	 */
	deleteKeys: () => {
		return ReactNativeBiometrics.deleteKeys();
	},
	/**
	 * Prompts user with biometrics dialog using the passed in prompt message and
	 * returns promise that resolves to a cryptographic signature of the payload
	 * @param {string} promptMessage
	 * @param {string} payload
	 * @returns {Promise}  Promise that resolves to cryptographic signature
	 */
	createSignature: (promptMessage, payload) => {
		return ReactNativeBiometrics.createSignature(promptMessage, payload);
	},
	/**
	 * Prompts user with biometrics dialog using the passed in prompt message and
	 * returns promise that resolves if the user passes, and
	 * rejects if the user fails or cancels
	 * @param {string} promptMessage
	 * @returns {Promise}  Promise that resolves if the user passes, and
	 * rejects if the user fails or cancels
	 */
	simplePrompt: promptMessage => {
		return ReactNativeBiometrics.simplePrompt(promptMessage);
	}
};

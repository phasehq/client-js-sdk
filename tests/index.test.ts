import Phase from "../index";

type PhaseAppId = `phApp:${string}`;

const SAMPLE_APP_ID =
  "phApp:v1:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
const SAMPLE_PLAINTEXT = "Hello, world!";
const SAMPLE_TAG = "sample_tag";
const PH_VERSION = "v1";

describe("Phase", () => {
  test("Check if constructor sets Phase appPubKey correctly", () => {
    const phase = new Phase(SAMPLE_APP_ID);
    expect(phase.appPubKey).toBe(SAMPLE_APP_ID.split(":")[2]);
  });


  test("Check if constructor throws an error for an invalid Phase AppID", () => {
    const invalidAppId = "phApp:version:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
    expect(() => new Phase(invalidAppId as any)).toThrowError("Invalid Phase appID");
  });

  test("Check if Phase encrypt returns a valid ph:*", async () => {
    const phase = new Phase(SAMPLE_APP_ID);
    const ciphertext = await phase.encrypt(SAMPLE_PLAINTEXT, SAMPLE_TAG);

    expect(ciphertext).toBeDefined();
    const segments = (ciphertext as string).split(":");

    expect(segments.length).toBe(5);
    expect(segments[0]).toBe("ph");
    expect(segments[1]).toBe(PH_VERSION);
    expect(segments[4]).toBe(SAMPLE_TAG);

    // Check if the one-time public key and ciphertext are valid hex strings
    expect(segments[2]).toMatch(/^[0-9a-f]+$/);
    expect(segments[3]).toMatch(/^[0-9a-f]+$/);
  });

  test("Check if Phase encrypt always produces ciphertexts (ph:*) of the same length for the same plaintext", async () => {
    const phase = new Phase(SAMPLE_APP_ID);
    const numOfTrials = 10;
    const ciphertextLengths = new Set<number>();

    for (let i = 0; i < numOfTrials; i++) {
      const ciphertext = await phase.encrypt(SAMPLE_PLAINTEXT, SAMPLE_TAG);
      ciphertextLengths.add((ciphertext as string).length);
    }

    expect(ciphertextLengths.size).toBe(1);
  });
});

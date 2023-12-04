import * as path from "path";
import { readdirSync  } from 'fs';

const FIXTURES_FILE = "./fixture_data"

const isObject = (value: unknown) => value && typeof value === "object";

// tslint:disable-next-line:no-var-requires
const resolveFixtures = (subDirectory: string, filter: any) =>
  require("require-all")({
    dirname: `${__dirname}/${subDirectory}`,
    filter: filter,
    excludeDirs: [".github", "tests"],
    map: (__: unknown, path: unknown) => {
      return `${path}`;
    },
  });

const suites = readdirSync(FIXTURES_FILE, { withFileTypes: true })
                .filter(dirent => dirent.isDirectory())
                .map(dirent => dirent.name);


interface mockRngInputs {
    readonly DST: string;
    readonly count: number;
}

interface mockRngParameters {
    readonly SEED: string;
    readonly commit?: mockRngInputs;
    readonly signature?: mockRngInputs;
    readonly proof?: mockRngInputs;
}

export interface CommitmentFixture {
    readonly caseName: string;
    readonly mockRngParameters: mockRngParameters;
    readonly committedMessages: string[];
    readonly proverBlind: string;
    readonly commitmentWithProof: string;
    readonly result: { valid: false; reason: string } | { valid: true };
}

export interface SignatureFixtureData {
  readonly caseName: string;
  readonly mockRngParameters: mockRngParameters;
  readonly signerKeyPair: {
    readonly publicKey: string;
    readonly secretKey: string;
  };
  readonly commitmentWithProof?: string;
  readonly header: string;
  readonly messages: string[];
  readonly committedMessages?: string[];
  readonly proverBlind?: string;
  readonly signerBlind?: string;
  readonly signature: string;
  readonly result: { valid: false; reason: string } | { valid: true };
}

export interface ProofFixtureData {
  readonly caseName: string;
  readonly mockRngParameters: mockRngParameters;
  readonly signerPublicKey: string;
  readonly signature: string;
  readonly commitmentWithProof: string;
  readonly proverBlind?: string;
  readonly signerBlind?: string;
  readonly header: string;
  readonly presentationHeader: string;
  readonly revealedMessages: { [index: string]: string };
  readonly revealedCommittedMessages: { [index: string]: string };
  readonly disclosedData: { [index: string]: string };
  readonly totalMessageCount: number;
  readonly proof: string;
  result: { valid: false; reason: string } | { valid: true };
}

export interface Fixture<T> {
  readonly name: string
  readonly value: T
}

const fetchNestedFixtures = <T>(name: string, input: any): ReadonlyArray<Fixture<T>> => {
  if (input.caseName || input.MsgGenerators || input.mockedScalars) {
    return [
      {
        name: path.basename(name).split(".")[0] as string,
        value: input,
      } as any,
    ];
  }
  if (!isObject(input)) {
    return [];
  }

  const extractedFixtures = Object.keys(input).map((key) =>
    fetchNestedFixtures(key, input[key])
  );
  return Array.prototype.concat.apply([], extractedFixtures);
};


const fetchPerSuiteFixtures = <T>(dir:string, filter = /.json$/) => {
  let fixtureMap = {}
  for (let suite of suites) {
    let suiteFixturesData = fetchNestedFixtures<T>(
      "", resolveFixtures(FIXTURES_FILE+"/"+suite+dir, filter)
      )
      .reduce((map, item: Fixture<T>) => {
        map = {
          ...map,
          [item.name]: item.value
        }
        return map
      }, {})

    fixtureMap = {
      ...fixtureMap,
      [suite]: suiteFixturesData
    }
  }
  
  return fixtureMap
}

export const commitmentFixtures = fetchPerSuiteFixtures<SignatureFixtureData>("/commit");
export const signatureFixtures = fetchPerSuiteFixtures<SignatureFixtureData>("/signature");
export const proofFixtures = fetchPerSuiteFixtures<ProofFixtureData>("/proof");

console.log(signatureFixtures);

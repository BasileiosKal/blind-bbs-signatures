import { promises } from "fs";
import * as path from "path";
import * as fixtures from "./fetchFixtures";
import get from "lodash.get";

// matching lines of the form "name = {{ $<fixture_path> }}" (for
// example "m_1 = {{ $messages[1] }}" etc).
const VARIABLE_REGEX = /(([^\S\n\t]*[a-zA-Z0-9_~]+\d*)\s=\s)?({{ \$)([a-zA-Z_|.|\-|\d|\[|\]]*)( }},?)$/gm

const DRAFT_NAME = "../draft-bbs-blind-signatures.md";
// const DRAFT_NAME = "./test.md";

const MAP_INTENT = 6;

const main = async () => {
  // Read the text of the draft out
  const filePath = path.join(process.env.PWD as string, DRAFT_NAME);
  let fileContents = (await promises.readFile(filePath)).toString();

  const results = Array.from(fileContents.matchAll(VARIABLE_REGEX)).map(
    (item: any) => {
      return { match: "{{ $" + item[4] + " }}", path: item[4], intent: item[1] };
    }
  );

  results.forEach((result) => {
    var value = get(fixtures, result.path);

    // turn the map: disclosed idx -> disclosed message to a list of
    // indexes for revealedMessages and revealedCommittedMessages for proofFixtures
    if (value != null && (result.path.includes("revealedMessages") || result.path.includes("revealedCommittedMessages")))
    {
      let keys: string[] = Object.keys(value);
      value = handle_array(keys, result.intent);
    } 
    else if (result.path.includes("disclosedData")) // handle the proof disclosed data
    {
      let map_keys = Object.keys(value);
      let map_values: string[] = Object.values(value);
      value = "{\n";
      for (let i = 0; i < map_keys.length; i++ ) {
        let prefix =  map_keys[i] + ": ";
        let v = prepare_value( map_values[i], " ".repeat(MAP_INTENT));

        value += " ".repeat((MAP_INTENT - prefix.length)) + prefix +  v + "\n";
      }
      value += "}";
    }
    else if (Array.isArray(value)) // handle values that are arrays
    {
      value = handle_array(value, result.intent);
    }
    else
    {
      value = prepare_value(value, result.intent);
    }

    if (value || value === '') {
      fileContents = fileContents.replace(result.match, value);
    }
  });

  // Write an updated copy of the file
  await promises.writeFile(filePath, fileContents);
};


function prepare_value(value: string, intent?: string): string {
  value = "\x22" + value + "\x22";

  let intent_len = intent ? intent.length : 0;
  let max_len = 71 - intent_len;
  if (max_len <= 0) {throw Error("Not enough space in the line to add the fixture")}

  // make everything 72 chars long
  if (value.length + intent_len > 72) {
    value = value.slice(0, max_len + 1) + "\n" + " ".repeat(intent_len + 1) + value.slice(max_len + 1);
  }
                                                                        
  for (let i = 1; i <= ~~(value.length/72); i++) {
    value = value.slice(0, 145 - intent_len + (i - 1)*73) + "\n" + " ".repeat(intent_len + 1) + value.slice(145 - intent_len + (i - 1)*73);
  }

  // remove trailing whitespace from the value to be added in the draft
  value = value.trim();
  return value
}

function handle_array(value: string[], intent?: string): string {
  let array_value = "[ ";
  for (let el of value.slice(0, -1)) {
    array_value = array_value + el + ", ";
  }
  array_value = array_value + value.slice(-1) + " ]";
  return prepare_value(array_value, intent)
  
}

main();

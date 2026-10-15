// test/helpers/reconcile_words.js — unit R-FGf (M1, the architect's ruling:
// nothing this service sends says "holds"): THE SECOND DIVERGENCE from
// reconcile.py. Where reconcile.py says a line "holds a duplicate key", the
// port says it "has" one; the rest of the answer is byte for byte. The
// conformance tests read the port's answer in reconcile.py's words through
// inPythonWords, and only where reconcile.py's answer says it.
"use strict";

const PYTHON_DUPLICATE = " holds a duplicate key and does not parse [duplicate_key_unparseable]";
const PORT_DUPLICATE = " has a duplicate key and does not parse [duplicate_key_unparseable]";

// The port's serialized answer `mine`, with its words put back as
// reconcile.py's `python` says them; null when the port says reconcile.py's
// words itself (it never may). An answer of reconcile.py's that does not
// say them is returned as the port gave it.
function inPythonWords(mine, python) {
  if (mine.includes(PYTHON_DUPLICATE)) return null;
  if (!python.includes(PYTHON_DUPLICATE)) return mine;
  return mine.split(PORT_DUPLICATE).join(PYTHON_DUPLICATE);
}

module.exports = { PYTHON_DUPLICATE, PORT_DUPLICATE, inPythonWords };

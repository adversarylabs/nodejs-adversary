# lang/nodejs — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `nodejs`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Node.js

## Mission

Review Node.js for dynamic code execution, shell injection, and disabled TLS verification.

## In scope (fair miss if humans raised it and we did not)

- eval/Function dynamic code
- Shell injection
- TLS verification disabled

## Out of scope (not a miss for this adversary)

- Pure type design (typescript)
- React XSS (react)

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading

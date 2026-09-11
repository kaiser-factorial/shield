// @ts-check
import js from "@eslint/js";
import tseslint from "typescript-eslint";

/**
 * Deliberately narrow, for the same reason the ruff config is: the point is to
 * catch real defects — an unused variable hiding a typo, a floating promise, a
 * `==` against null — not to enforce house style on code that already reads
 * consistently. Nothing here reformats anything.
 *
 * The type-aware rules are worth the slower run: no-floating-promises is the
 * one that matters most in this codebase, where an unawaited scan would mean a
 * check that silently never happened.
 */
export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "bench/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      // `any` is load-bearing here: the wrappers match SDK shapes structurally
      // without importing the SDKs, so the surface is genuinely untyped. The
      // inline eslint-disable comments already mark each spot.
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      // An unused argument named with a leading underscore is intentional.
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      // Empty catch blocks are a deliberate pattern in this codebase:
      // observation must never break a caller's stream. They carry a comment.
      "no-empty": ["error", { allowEmptyCatch: true }],
      // The wrappers pull methods off SDK objects and re-bind them explicitly
      // (`fn.call(this.inner.messages, ...)`). That is the intended shape, not
      // an accidental unbinding.
      "@typescript-eslint/unbound-method": "off",
      // Reasons are interpolated into event details from SDK payloads of
      // genuinely unknown type; stringifying them is the point.
      "@typescript-eslint/restrict-template-expressions": "off",
    },
  },
  {
    // Tests build fake SDK objects and assert on loose shapes. `test(...)` from
    // node:test returns a promise the runner owns, so every call site would
    // otherwise be a floating-promise error.
    files: ["test/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/no-floating-promises": "off",
      "@typescript-eslint/no-unnecessary-type-assertion": "off",
    },
  },
  {
    // The async-iterator protocol requires `return` and `throw` to be async
    // whether or not their bodies await.
    files: ["src/stream.ts"],
    rules: { "@typescript-eslint/require-await": "off" },
  },
);

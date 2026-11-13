// The languages FlareID's sign-in pages ship in. To add one, copy en.json to
// <code>.json, translate the messages, import it here and add it to LOCALES
// (see CONTRIBUTING.md, "Adding a language"); test/i18n.test.ts checks that it
// has exactly en.json's keys and placeholders.
//
// The JSON is imported, so it is bundled into the Worker at build time: no
// request ever reads a file.
import en from "./en.json";
import fr from "./fr.json";
import de from "./de.json";

export interface LocaleFile {
  _meta: {
    /** BCP 47 tag, lower-case primary subtag (e.g. "fr", "pt-br"). Must match the key in LOCALES. */
    code: string;
    /** In English, for the admin console. */
    name: string;
    /** In the language itself, for the language picker. */
    nativeName: string;
    /** "rtl" for right-to-left scripts (Arabic, Hebrew, ...). */
    dir: "ltr" | "rtl" | string;
    source?: boolean;
    /** True until a native speaker has reviewed the translation. */
    machineAssisted?: boolean;
    reviewedBy?: string[];
    notes?: string;
  };
  messages: Record<string, string>;
}

/** Keyed by locale code; the order is the language picker's. */
export const LOCALES: Record<string, LocaleFile> = { en, fr, de };

/** The source locale: every key exists here, and it is the fallback for any key a translation lacks. */
export const SOURCE_LOCALE = en;

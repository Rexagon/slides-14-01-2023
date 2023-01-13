import { defineShikiSetup } from "@slidev/types";
const path = require("path");

export default defineShikiSetup(async ({ loadTheme }) => {
  return {
    theme: {
      dark: await loadTheme(
        path.resolve(__dirname, "../themes/gruvbox-dark.json")
      ),
      light: "min-light",
    },
  };
});

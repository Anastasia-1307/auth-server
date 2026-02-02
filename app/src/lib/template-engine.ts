import { readFileSync } from "fs";

export function renderTemplate(templatePath: string, variables: Record<string, string>): string {
  const template = readFileSync(templatePath, "utf-8");
  
  return Object.entries(variables).reduce(
    (result, [key, value]) => result.replace(new RegExp(`{{${key}}}`, "g"), value),
    template
  );
}

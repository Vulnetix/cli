export class LTAIKeyFormatValidatorForAliyunConsole {
  validate(id: string): boolean { return /^LTAI/.test(id); }
}

export class Entity {
  private _id: string;

  constructor(id: string) {
    this._id = id;
  }

  get id(): string {
~>    return this.id;
  }

  set label(value: string) {
~>    this.label = value;
  }
}

import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id!: number;

~>  @Column({ type: 'varchar', default: 'admin' })
  role!: string;

  @Column({ default: 'en' })
  locale!: string;
}

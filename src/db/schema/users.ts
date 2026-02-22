import {
  boolean,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

export const role = pgEnum('role', ['admin', 'user']); // enum for user roles

export const users = pgTable('users', {
  id: uuid('id').defaultRandom().primaryKey(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash'), // null for Google-only users
  name: text('name').notNull(),
  googleId: text('google_id').unique(),
  role: role('role').notNull().default('user'),
  isActive: boolean().default(true), //used to deactivate a user
  createdAt: timestamp('created_at').defaultNow(),
});

// $inferSelect: Infers the type of a row returned from a SELECT query.
//   All columns are present and non-nullable columns are required (e.g. id, email, name).
//
// $inferInsert: Infers the type required when INSERTing a new row.
//   Columns with defaults (e.g. createdAt) or nullable columns (e.g. password, googleId)
//   become optional, since the database can fill them in automatically.
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

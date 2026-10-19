CREATE TABLE `apns_devices` (
	`token` text PRIMARY KEY NOT NULL,
	`environment` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `approvals` (
	`id` text PRIMARY KEY NOT NULL,
	`database_id` text NOT NULL,
	`user_id` text NOT NULL,
	`surface` text NOT NULL,
	`sql` text NOT NULL,
	`params` text,
	`statements` text NOT NULL,
	`asked` text NOT NULL,
	`operations` text NOT NULL,
	`tables` text NOT NULL,
	`estimate` text,
	`session` text,
	`status` text DEFAULT 'pending' NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`decided_at` integer,
	`grant_id` text,
	FOREIGN KEY (`database_id`) REFERENCES `databases`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `approvals_status_idx` ON `approvals` (`status`,`created_at`);--> statement-breakpoint
CREATE TABLE `audit` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`ts` integer NOT NULL,
	`database_id` text NOT NULL,
	`user_id` text NOT NULL,
	`surface` text NOT NULL,
	`sql` text NOT NULL,
	`operations` text NOT NULL,
	`tables` text NOT NULL,
	`decision` text NOT NULL,
	`rule_id` text,
	`approval_id` text,
	`row_count` integer,
	`sqlstate` text,
	`error` text,
	`duration_ms` integer
);
--> statement-breakpoint
CREATE INDEX `audit_database_idx` ON `audit` (`database_id`);--> statement-breakpoint
CREATE INDEX `audit_user_idx` ON `audit` (`user_id`);--> statement-breakpoint
CREATE TABLE `databases` (
	`id` text PRIMARY KEY NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`engine` text DEFAULT 'postgres' NOT NULL,
	`host` text NOT NULL,
	`port` integer NOT NULL,
	`database` text NOT NULL,
	`user` text NOT NULL,
	`password` text DEFAULT '' NOT NULL,
	`sslmode` text DEFAULT 'prefer' NOT NULL,
	`readonly_user` text,
	`readonly_password` text,
	`default_read` text DEFAULT 'allow' NOT NULL,
	`default_write` text DEFAULT 'approve' NOT NULL,
	`default_ddl` text DEFAULT 'approve' NOT NULL,
	`default_admin` text DEFAULT 'deny' NOT NULL,
	`statement_timeout_ms` integer DEFAULT 30000 NOT NULL,
	`max_rows` integer DEFAULT 200 NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `databases_slug_unique` ON `databases` (`slug`);--> statement-breakpoint
CREATE TABLE `grants` (
	`id` text PRIMARY KEY NOT NULL,
	`database_id` text NOT NULL,
	`user_id` text,
	`operation` text,
	`table_pattern` text,
	`expires_at` integer,
	`approval_id` text,
	`note` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`database_id`) REFERENCES `databases`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `grants_database_idx` ON `grants` (`database_id`);--> statement-breakpoint
CREATE TABLE `push_subscriptions` (
	`endpoint` text PRIMARY KEY NOT NULL,
	`p256dh` text NOT NULL,
	`auth` text NOT NULL,
	`user_agent` text,
	`created_at` integer NOT NULL,
	`last_success_at` integer
);
--> statement-breakpoint
CREATE TABLE `rules` (
	`id` text PRIMARY KEY NOT NULL,
	`database_id` text NOT NULL,
	`user_id` text,
	`operation` text NOT NULL,
	`table_pattern` text,
	`action` text NOT NULL,
	`note` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`database_id`) REFERENCES `databases`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `rules_database_idx` ON `rules` (`database_id`);--> statement-breakpoint
CREATE TABLE `settings` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `user_databases` (
	`user_id` text NOT NULL,
	`database_id` text NOT NULL,
	`allow_mcp` integer DEFAULT true NOT NULL,
	`allow_wire` integer DEFAULT true NOT NULL,
	PRIMARY KEY(`user_id`, `database_id`),
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`database_id`) REFERENCES `databases`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`username` text NOT NULL,
	`token_hash` text NOT NULL,
	`token_prefix` text NOT NULL,
	`scram_salt` text NOT NULL,
	`scram_iterations` integer NOT NULL,
	`scram_stored_key` text NOT NULL,
	`scram_server_key` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL,
	`last_used_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_username_unique` ON `users` (`username`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_tokenHash_unique` ON `users` (`token_hash`);
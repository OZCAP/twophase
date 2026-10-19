ALTER TABLE `approvals` ADD `verbs` text DEFAULT '[]' NOT NULL;--> statement-breakpoint
ALTER TABLE `audit` ADD `verbs` text DEFAULT '[]' NOT NULL;
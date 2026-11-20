-- Gap #24: keep what a tool said, what it said before its last change, and why it is hidden or flagged.
-- Descriptions are upstream text, redacted before storage like every other payload (MP-C3).
ALTER TABLE tool_pins ADD COLUMN description TEXT;
ALTER TABLE tool_pins ADD COLUMN previous_description TEXT;
ALTER TABLE tool_pins ADD COLUMN reason TEXT;

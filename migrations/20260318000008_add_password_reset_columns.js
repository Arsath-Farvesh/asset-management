exports.up = async function up(knex) {
  const hasTokenHash = await knex.schema.hasColumn('users', 'reset_password_token_hash');
  const hasTokenExpiry = await knex.schema.hasColumn('users', 'reset_password_expires_at');

  return knex.schema.alterTable('users', (table) => {
    if (!hasTokenHash) {
      table.string('reset_password_token_hash', 255).nullable().index();
    }

    if (!hasTokenExpiry) {
      table.timestamp('reset_password_expires_at').nullable().index();
    }
  });
};

exports.down = async function down(knex) {
  const hasTokenHash = await knex.schema.hasColumn('users', 'reset_password_token_hash');
  const hasTokenExpiry = await knex.schema.hasColumn('users', 'reset_password_expires_at');

  return knex.schema.alterTable('users', (table) => {
    if (hasTokenExpiry) {
      table.dropColumn('reset_password_expires_at');
    }

    if (hasTokenHash) {
      table.dropColumn('reset_password_token_hash');
    }
  });
};
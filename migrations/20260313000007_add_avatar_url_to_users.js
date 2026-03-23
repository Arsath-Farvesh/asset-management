exports.up = async function (knex) {
  const hasAvatarUrl = await knex.schema.hasColumn('users', 'avatar_url');
  if (!hasAvatarUrl) {
    await knex.schema.table('users', (table) => {
      table.text('avatar_url').nullable();
    });
  }
};

exports.down = async function (knex) {
  const hasAvatarUrl = await knex.schema.hasColumn('users', 'avatar_url');
  if (hasAvatarUrl) {
    await knex.schema.table('users', (table) => {
      table.dropColumn('avatar_url');
    });
  }
};
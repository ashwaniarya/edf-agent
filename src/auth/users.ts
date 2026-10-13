export type UserRecord = { id: string; email: string; name: string };
export type UserDirectory = { findById(id: string): Promise<UserRecord | null> };

type AuthWithUsers = {
  $context: Promise<{ internalAdapter: { findUserById(id: string): Promise<UserRecord | null> } }>;
};

export function userDirectoryFrom(auth: AuthWithUsers): UserDirectory {
  return {
    async findById(id) {
      const user = await (await auth.$context).internalAdapter.findUserById(id);
      return user ? { id: user.id, email: user.email, name: user.name } : null;
    },
  };
}

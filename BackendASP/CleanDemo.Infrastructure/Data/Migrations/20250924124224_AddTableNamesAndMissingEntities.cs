using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace CleanDemo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTableNamesAndMissingEntities : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Enrollments_User_UserId",
                table: "Enrollments");

            migrationBuilder.DropForeignKey(
                name: "FK_ExampleVocabulary_Vocab_VocabId",
                table: "ExampleVocabulary");

            migrationBuilder.DropForeignKey(
                name: "FK_RoleUser_Role_RolesRoleId",
                table: "RoleUser");

            migrationBuilder.DropForeignKey(
                name: "FK_RoleUser_User_UsersUserId",
                table: "RoleUser");

            migrationBuilder.DropForeignKey(
                name: "FK_User_StateUser_StateUserId",
                table: "User");

            migrationBuilder.DropForeignKey(
                name: "FK_UserProgresses_User_UserId",
                table: "UserProgresses");

            migrationBuilder.DropForeignKey(
                name: "FK_UserVocabs_User_UserId",
                table: "UserVocabs");

            migrationBuilder.DropForeignKey(
                name: "FK_UserVocabs_Vocab_VocabId",
                table: "UserVocabs");

            migrationBuilder.DropForeignKey(
                name: "FK_Vocab_Topic_TopicId",
                table: "Vocab");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Vocab",
                table: "Vocab");

            migrationBuilder.DropPrimaryKey(
                name: "PK_User",
                table: "User");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Topic",
                table: "Topic");

            migrationBuilder.DropPrimaryKey(
                name: "PK_StateUser",
                table: "StateUser");

            migrationBuilder.DropPrimaryKey(
                name: "PK_RoleUser",
                table: "RoleUser");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Role",
                table: "Role");

            migrationBuilder.DropPrimaryKey(
                name: "PK_ExampleVocabulary",
                table: "ExampleVocabulary");

            migrationBuilder.DropColumn(
                name: "DateOfBirth",
                table: "User");

            migrationBuilder.DropColumn(
                name: "IDState",
                table: "User");

            migrationBuilder.RenameTable(
                name: "Vocab",
                newName: "Vocabs");

            migrationBuilder.RenameTable(
                name: "User",
                newName: "Users");

            migrationBuilder.RenameTable(
                name: "Topic",
                newName: "Topics");

            migrationBuilder.RenameTable(
                name: "StateUser",
                newName: "StateUsers");

            migrationBuilder.RenameTable(
                name: "RoleUser",
                newName: "UserRoles");

            migrationBuilder.RenameTable(
                name: "Role",
                newName: "Roles");

            migrationBuilder.RenameTable(
                name: "ExampleVocabulary",
                newName: "ExampleVocabularies");

            migrationBuilder.RenameIndex(
                name: "IX_Vocab_TopicId",
                table: "Vocabs",
                newName: "IX_Vocabs_TopicId");

            migrationBuilder.RenameColumn(
                name: "Name",
                table: "Users",
                newName: "SureName");

            migrationBuilder.RenameIndex(
                name: "IX_User_StateUserId",
                table: "Users",
                newName: "IX_Users_StateUserId");

            migrationBuilder.RenameIndex(
                name: "IX_RoleUser_UsersUserId",
                table: "UserRoles",
                newName: "IX_UserRoles_UsersUserId");

            migrationBuilder.RenameIndex(
                name: "IX_ExampleVocabulary_VocabId",
                table: "ExampleVocabularies",
                newName: "IX_ExampleVocabularies_VocabId");

            migrationBuilder.AlterColumn<string>(
                name: "Email",
                table: "Users",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AddColumn<string>(
                name: "LastName",
                table: "Users",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "PasswordHash",
                table: "Users",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "PhoneNumber",
                table: "Users",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Vocabs",
                table: "Vocabs",
                column: "VocabId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Users",
                table: "Users",
                column: "UserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Topics",
                table: "Topics",
                column: "TopicId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_StateUsers",
                table: "StateUsers",
                column: "StateUserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_UserRoles",
                table: "UserRoles",
                columns: new[] { "RolesRoleId", "UsersUserId" });

            migrationBuilder.AddPrimaryKey(
                name: "PK_Roles",
                table: "Roles",
                column: "RoleId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_ExampleVocabularies",
                table: "ExampleVocabularies",
                column: "ExampleVocabularyId");

            migrationBuilder.InsertData(
                table: "Roles",
                columns: new[] { "RoleId", "Name" },
                values: new object[,]
                {
                    { 1, "Admin" },
                    { 2, "User" }
                });

            migrationBuilder.InsertData(
                table: "StateUsers",
                columns: new[] { "StateUserId", "Description", "Name" },
                values: new object[] { 1, "Active user state", "Active" });

            migrationBuilder.InsertData(
                table: "Users",
                columns: new[] { "UserId", "CreatedAt", "Email", "LastName", "PasswordHash", "PhoneNumber", "StateUserId", "Status", "SureName", "UpdatedAt" },
                values: new object[] { 1, new DateTime(2025, 9, 24, 12, 42, 24, 531, DateTimeKind.Utc).AddTicks(6956), "admin@studyenglish.com", "System", "$2a$11$example.hash.for.admin", "1234567890", 1, 0, "Admin", new DateTime(2025, 9, 24, 12, 42, 24, 531, DateTimeKind.Utc).AddTicks(6957) });

            migrationBuilder.InsertData(
                table: "UserRoles",
                columns: new[] { "RolesRoleId", "UsersUserId" },
                values: new object[] { 1, 1 });

            migrationBuilder.CreateIndex(
                name: "IX_Users_Email",
                table: "Users",
                column: "Email",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Enrollments_Users_UserId",
                table: "Enrollments",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_ExampleVocabularies_Vocabs_VocabId",
                table: "ExampleVocabularies",
                column: "VocabId",
                principalTable: "Vocabs",
                principalColumn: "VocabId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserProgresses_Users_UserId",
                table: "UserProgresses",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserRoles_Roles_RolesRoleId",
                table: "UserRoles",
                column: "RolesRoleId",
                principalTable: "Roles",
                principalColumn: "RoleId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserRoles_Users_UsersUserId",
                table: "UserRoles",
                column: "UsersUserId",
                principalTable: "Users",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Users_StateUsers_StateUserId",
                table: "Users",
                column: "StateUserId",
                principalTable: "StateUsers",
                principalColumn: "StateUserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserVocabs_Users_UserId",
                table: "UserVocabs",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserVocabs_Vocabs_VocabId",
                table: "UserVocabs",
                column: "VocabId",
                principalTable: "Vocabs",
                principalColumn: "VocabId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Vocabs_Topics_TopicId",
                table: "Vocabs",
                column: "TopicId",
                principalTable: "Topics",
                principalColumn: "TopicId",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Enrollments_Users_UserId",
                table: "Enrollments");

            migrationBuilder.DropForeignKey(
                name: "FK_ExampleVocabularies_Vocabs_VocabId",
                table: "ExampleVocabularies");

            migrationBuilder.DropForeignKey(
                name: "FK_UserProgresses_Users_UserId",
                table: "UserProgresses");

            migrationBuilder.DropForeignKey(
                name: "FK_UserRoles_Roles_RolesRoleId",
                table: "UserRoles");

            migrationBuilder.DropForeignKey(
                name: "FK_UserRoles_Users_UsersUserId",
                table: "UserRoles");

            migrationBuilder.DropForeignKey(
                name: "FK_Users_StateUsers_StateUserId",
                table: "Users");

            migrationBuilder.DropForeignKey(
                name: "FK_UserVocabs_Users_UserId",
                table: "UserVocabs");

            migrationBuilder.DropForeignKey(
                name: "FK_UserVocabs_Vocabs_VocabId",
                table: "UserVocabs");

            migrationBuilder.DropForeignKey(
                name: "FK_Vocabs_Topics_TopicId",
                table: "Vocabs");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Vocabs",
                table: "Vocabs");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Users",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_Email",
                table: "Users");

            migrationBuilder.DropPrimaryKey(
                name: "PK_UserRoles",
                table: "UserRoles");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Topics",
                table: "Topics");

            migrationBuilder.DropPrimaryKey(
                name: "PK_StateUsers",
                table: "StateUsers");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Roles",
                table: "Roles");

            migrationBuilder.DropPrimaryKey(
                name: "PK_ExampleVocabularies",
                table: "ExampleVocabularies");

            migrationBuilder.DeleteData(
                table: "Roles",
                keyColumn: "RoleId",
                keyValue: 2);

            migrationBuilder.DeleteData(
                table: "UserRoles",
                keyColumns: new[] { "RolesRoleId", "UsersUserId" },
                keyValues: new object[] { 1, 1 });

            migrationBuilder.DeleteData(
                table: "Roles",
                keyColumn: "RoleId",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "Users",
                keyColumn: "UserId",
                keyValue: 1);

            migrationBuilder.DeleteData(
                table: "StateUsers",
                keyColumn: "StateUserId",
                keyValue: 1);

            migrationBuilder.DropColumn(
                name: "LastName",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "PasswordHash",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "PhoneNumber",
                table: "Users");

            migrationBuilder.RenameTable(
                name: "Vocabs",
                newName: "Vocab");

            migrationBuilder.RenameTable(
                name: "Users",
                newName: "User");

            migrationBuilder.RenameTable(
                name: "UserRoles",
                newName: "RoleUser");

            migrationBuilder.RenameTable(
                name: "Topics",
                newName: "Topic");

            migrationBuilder.RenameTable(
                name: "StateUsers",
                newName: "StateUser");

            migrationBuilder.RenameTable(
                name: "Roles",
                newName: "Role");

            migrationBuilder.RenameTable(
                name: "ExampleVocabularies",
                newName: "ExampleVocabulary");

            migrationBuilder.RenameIndex(
                name: "IX_Vocabs_TopicId",
                table: "Vocab",
                newName: "IX_Vocab_TopicId");

            migrationBuilder.RenameColumn(
                name: "SureName",
                table: "User",
                newName: "Name");

            migrationBuilder.RenameIndex(
                name: "IX_Users_StateUserId",
                table: "User",
                newName: "IX_User_StateUserId");

            migrationBuilder.RenameIndex(
                name: "IX_UserRoles_UsersUserId",
                table: "RoleUser",
                newName: "IX_RoleUser_UsersUserId");

            migrationBuilder.RenameIndex(
                name: "IX_ExampleVocabularies_VocabId",
                table: "ExampleVocabulary",
                newName: "IX_ExampleVocabulary_VocabId");

            migrationBuilder.AlterColumn<string>(
                name: "Email",
                table: "User",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AddColumn<DateTime>(
                name: "DateOfBirth",
                table: "User",
                type: "datetime2",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            migrationBuilder.AddColumn<int>(
                name: "IDState",
                table: "User",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddPrimaryKey(
                name: "PK_Vocab",
                table: "Vocab",
                column: "VocabId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_User",
                table: "User",
                column: "UserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_RoleUser",
                table: "RoleUser",
                columns: new[] { "RolesRoleId", "UsersUserId" });

            migrationBuilder.AddPrimaryKey(
                name: "PK_Topic",
                table: "Topic",
                column: "TopicId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_StateUser",
                table: "StateUser",
                column: "StateUserId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_Role",
                table: "Role",
                column: "RoleId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_ExampleVocabulary",
                table: "ExampleVocabulary",
                column: "ExampleVocabularyId");

            migrationBuilder.AddForeignKey(
                name: "FK_Enrollments_User_UserId",
                table: "Enrollments",
                column: "UserId",
                principalTable: "User",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_ExampleVocabulary_Vocab_VocabId",
                table: "ExampleVocabulary",
                column: "VocabId",
                principalTable: "Vocab",
                principalColumn: "VocabId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RoleUser_Role_RolesRoleId",
                table: "RoleUser",
                column: "RolesRoleId",
                principalTable: "Role",
                principalColumn: "RoleId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_RoleUser_User_UsersUserId",
                table: "RoleUser",
                column: "UsersUserId",
                principalTable: "User",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_User_StateUser_StateUserId",
                table: "User",
                column: "StateUserId",
                principalTable: "StateUser",
                principalColumn: "StateUserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserProgresses_User_UserId",
                table: "UserProgresses",
                column: "UserId",
                principalTable: "User",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserVocabs_User_UserId",
                table: "UserVocabs",
                column: "UserId",
                principalTable: "User",
                principalColumn: "UserId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_UserVocabs_Vocab_VocabId",
                table: "UserVocabs",
                column: "VocabId",
                principalTable: "Vocab",
                principalColumn: "VocabId",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_Vocab_Topic_TopicId",
                table: "Vocab",
                column: "TopicId",
                principalTable: "Topic",
                principalColumn: "TopicId",
                onDelete: ReferentialAction.Cascade);
        }
    }
}

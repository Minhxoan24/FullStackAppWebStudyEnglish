using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CleanDemo.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemoveStateUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Users_StateUsers_StateUserId",
                table: "Users");

            migrationBuilder.DropTable(
                name: "StateUsers");

            migrationBuilder.DropIndex(
                name: "IX_Users_StateUserId",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "StateUserId",
                table: "Users");

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "UserId",
                keyValue: 1,
                columns: new[] { "CreatedAt", "UpdatedAt" },
                values: new object[] { new DateTime(2025, 9, 24, 12, 54, 48, 837, DateTimeKind.Utc).AddTicks(8820), new DateTime(2025, 9, 24, 12, 54, 48, 837, DateTimeKind.Utc).AddTicks(8820) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "StateUserId",
                table: "Users",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateTable(
                name: "StateUsers",
                columns: table => new
                {
                    StateUserId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Description = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_StateUsers", x => x.StateUserId);
                });

            migrationBuilder.InsertData(
                table: "StateUsers",
                columns: new[] { "StateUserId", "Description", "Name" },
                values: new object[] { 1, "Active user state", "Active" });

            migrationBuilder.UpdateData(
                table: "Users",
                keyColumn: "UserId",
                keyValue: 1,
                columns: new[] { "CreatedAt", "StateUserId", "UpdatedAt" },
                values: new object[] { new DateTime(2025, 9, 24, 12, 42, 24, 531, DateTimeKind.Utc).AddTicks(6956), 1, new DateTime(2025, 9, 24, 12, 42, 24, 531, DateTimeKind.Utc).AddTicks(6957) });

            migrationBuilder.CreateIndex(
                name: "IX_Users_StateUserId",
                table: "Users",
                column: "StateUserId",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Users_StateUsers_StateUserId",
                table: "Users",
                column: "StateUserId",
                principalTable: "StateUsers",
                principalColumn: "StateUserId",
                onDelete: ReferentialAction.Cascade);
        }
    }
}

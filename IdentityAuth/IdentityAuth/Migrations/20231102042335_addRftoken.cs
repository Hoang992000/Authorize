using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace IdentityAuth.Migrations
{
    /// <inheritdoc />
    public partial class addRftoken : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "3d863164-1bd9-49a8-ba35-9010afe96a41");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5d7c985e-6746-4c82-bd3b-e2c9a80b284d");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "e14f054f-8cd2-4ecf-b6eb-45900bd79305");

            migrationBuilder.CreateTable(
                name: "refreshTokens",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Token = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    ExpiredTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_refreshTokens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_refreshTokens_AspNetUsers_UserId",
                        column: x => x.UserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "62da92e8-678c-44e8-a2a7-1a5e423e4cab", "2", "User", "User" },
                    { "9562f60b-0b99-4878-a041-1be09c1b16a1", "1", "Admin", "Admin" },
                    { "d5f59389-812f-464a-ac1d-26de5d520238", "3", "HR", "HR" }
                });

            migrationBuilder.CreateIndex(
                name: "IX_refreshTokens_UserId",
                table: "refreshTokens",
                column: "UserId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "refreshTokens");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "62da92e8-678c-44e8-a2a7-1a5e423e4cab");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9562f60b-0b99-4878-a041-1be09c1b16a1");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "d5f59389-812f-464a-ac1d-26de5d520238");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "3d863164-1bd9-49a8-ba35-9010afe96a41", "2", "User", "User" },
                    { "5d7c985e-6746-4c82-bd3b-e2c9a80b284d", "3", "HR", "HR" },
                    { "e14f054f-8cd2-4ecf-b6eb-45900bd79305", "1", "Admin", "Admin" }
                });
        }
    }
}

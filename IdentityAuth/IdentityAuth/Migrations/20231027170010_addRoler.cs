using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace IdentityAuth.Migrations
{
    /// <inheritdoc />
    public partial class addRoler : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
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
        }
    }
}

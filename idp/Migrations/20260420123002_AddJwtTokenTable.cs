using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace idp.Migrations
{
    /// <inheritdoc />
    public partial class AddJwtTokenTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "JwtTokens",
                columns: table => new
                {
                    Jti = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Expiry = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_JwtTokens", x => x.Jti);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "JwtTokens");
        }
    }
}

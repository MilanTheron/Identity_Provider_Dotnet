using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace idp.Migrations
{
    /// <inheritdoc />
    public partial class AddNonce : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ClientSecret",
                table: "OAuthClients",
                type: "TEXT",
                maxLength: 2048,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Nonce",
                table: "AuthorizationCodes",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ClientSecret",
                table: "OAuthClients");

            migrationBuilder.DropColumn(
                name: "Nonce",
                table: "AuthorizationCodes");
        }
    }
}

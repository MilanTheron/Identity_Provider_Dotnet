using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace idp.Migrations
{
    /// <inheritdoc />
    public partial class InitFix : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<Guid>(
                name: "DeviceId",
                table: "Users",
                type: "TEXT",
                nullable: true,
                oldClrType: typeof(Guid),
                oldType: "TEXT");

            migrationBuilder.CreateIndex(
                name: "IX_Users_DeviceId",
                table: "Users",
                column: "DeviceId");

            migrationBuilder.AddForeignKey(
                name: "FK_Users_Devices_DeviceId",
                table: "Users",
                column: "DeviceId",
                principalTable: "Devices",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Users_Devices_DeviceId",
                table: "Users");

            migrationBuilder.DropIndex(
                name: "IX_Users_DeviceId",
                table: "Users");

            migrationBuilder.AlterColumn<Guid>(
                name: "DeviceId",
                table: "Users",
                type: "TEXT",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"),
                oldClrType: typeof(Guid),
                oldType: "TEXT",
                oldNullable: true);
        }
    }
}

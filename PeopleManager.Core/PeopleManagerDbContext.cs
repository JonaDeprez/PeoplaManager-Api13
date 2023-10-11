using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PeopleManager.Model;

namespace PeopleManager.Core
{
    public class PeopleManagerDbContext : IdentityDbContext
    {

        public PeopleManagerDbContext(DbContextOptions<PeopleManagerDbContext> options) : base(options)
        {

        }

        public DbSet<Person> People => Set<Person>();
        public DbSet<Vehicle> Vehicles => Set<Vehicle>();

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Vehicle>()
                .HasOne(v => v.ResponsiblePerson)
                .WithMany(p => p.ResponsibleForVehicles)
                .HasForeignKey(v => v.ResponsiblePersonId)
                .IsRequired(false);

            base.OnModelCreating(modelBuilder);
        }

        public void Seed()
        {
            var bavoPerson = new Person
            {
                FirstName = "Bavo",
                LastName = "Ketels",
                Email = "bavo.ketels@vives.be",
                Description = "Lector"
            };
            var wimPerson = new Person
            {
                FirstName = "Wim",
                LastName = "Engelen",
                Email = "wim.engelen@vives.be",
                Description = "Opleidingshoofd"
            };

            People.AddRange(new List<Person>
            {
                bavoPerson,
                new Person{FirstName = "Isabelle", LastName = "Vandoorne", Email = "isabelle.vandoorne@vives.be" },
                wimPerson,
                new Person{FirstName = "Ebe", LastName = "Deketelaere", Email = "ebe.deketelaere@vives.be" }
            });

            Vehicles.AddRange(new[] {
                new Vehicle{LicensePlate = "1-ABC-123", ResponsiblePerson = bavoPerson},
                new Vehicle{LicensePlate = "THE_BOSS", Brand= "Ferrari", Type="448", ResponsiblePerson = wimPerson},
                new Vehicle{LicensePlate = "SALES_GUY_1", Brand= "Audi", Type="e-tron", ResponsiblePerson = bavoPerson},
                new Vehicle{LicensePlate = "DESK_1", Brand= "Fiat", Type="Punto", ResponsiblePerson = bavoPerson}});

            SaveChanges();
        }
    }
}

import click
from click import Choice

from find_rel32_ksymtab import Rel32KsymtabFinder
from find_ksymtab import KsymtabFinder


@click.command()
@click.argument('filename')
@click.argument('bitsize', type=click.Choice(['64', '32']))
@click.option(
    '--endianess',
    help='Architecture endianess',
    type=click.Choice(['LE', 'BE']),
    default="LE",
    show_default=True
)
@click.option('--linux-ver-override', help='Linux version X.Y.Z', default="5.4.0", show_default=True)
@click.option(
    '--ksymtab-type',
    help='Ksymtab find type',
    type=click.Choice(['normal', 'rel32']), default="normal", show_default=True)
def ksymtab_finder(filename, bitsize, endianess, linux_ver_override, ksymtab_type):
    linux_ver_override = tuple(map(
        lambda x: int(x),
        linux_ver_override.split(".")
    ))
    bitsize = int(bitsize)

    finder = KsymtabFinder(filename, bitsize, linux_ver_override, endianess)

    if ksymtab_type == "rel32":
        finder = Rel32KsymtabFinder(filename, bitsize, linux_ver_override, endianess)

    symbols = finder.find_and_parse_ksymtab()

    print(symbols)

if __name__ == '__main__':
    ksymtab_finder()

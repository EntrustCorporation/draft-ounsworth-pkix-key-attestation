import click

@click.group()
def cli():
    pass

@cli.command()
def demo():
    """Create devices and an application key"""
    from .demo import run
    run()

cli()

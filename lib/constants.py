from pathlib import Path

base_folder = Path(__file__).parent.parent
output_folder_path = base_folder.joinpath('output_files')
latest_report_folder = output_folder_path / 'latest_report'
stale_report_folder = output_folder_path / 'stale_report'
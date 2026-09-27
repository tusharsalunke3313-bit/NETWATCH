"""
Tests for NETWATCH Phase 13 PDF reporting.
"""

import tempfile
import unittest
from pathlib import Path

from reportlab.pdfbase.pdfmetrics import stringWidth

from assessment.assessment_engine import AssessmentEngine
from reporting.pdf_report import (
    PDFReportError,
    PDFReportGenerator,
    format_report_information,
)


class PDFReportTests(unittest.TestCase):

    def setUp(self):
        self.generator = PDFReportGenerator()

        self.assessment = (
            AssessmentEngine()
            .build_sample_assessment()
        )

    def test_generator_imports(self):
        self.assertIsInstance(
            self.generator,
            PDFReportGenerator,
        )

    def test_empty_assessment_rejected(self):
        with self.assertRaises(PDFReportError):
            self.generator.generate({})

    def test_sample_assessment_generates_pdf(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = PDFReportGenerator(
                output_directory=temp_dir
            )

            path = generator.generate(
                self.assessment
            )

            self.assertTrue(path.exists())
            self.assertEqual(
                path.suffix.lower(),
                ".pdf",
            )
            self.assertGreater(
                path.stat().st_size,
                1000,
            )

    def test_custom_filename(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = PDFReportGenerator(
                output_directory=temp_dir
            )

            path = generator.generate(
                self.assessment,
                filename="custom_report.pdf",
            )

            self.assertEqual(
                path.name,
                "custom_report.pdf",
            )
            self.assertTrue(path.exists())

    def test_pdf_header_is_valid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = PDFReportGenerator(
                output_directory=temp_dir
            )

            path = generator.generate(
                self.assessment
            )

            with path.open(
                "rb"
            ) as report_file:
                header = report_file.read(5)

            self.assertEqual(
                header,
                b"%PDF-",
            )

    def test_report_information(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = PDFReportGenerator(
                output_directory=temp_dir
            )

            path = generator.generate(
                self.assessment
            )

            information = format_report_information(
                path
            )

            self.assertIn(
                "PDF REPORT",
                information,
            )
            self.assertIn(
                str(path),
                information,
            )
            self.assertIn(
                "Exists: Yes",
                information,
            )

    def test_report_can_use_mapping(self):
        assessment_data = (
            self.assessment.to_dict()
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            generator = PDFReportGenerator(
                output_directory=temp_dir
            )

            path = generator.generate(
                assessment_data,
                filename="mapping_report.pdf",
            )

            self.assertTrue(
                Path(path).exists()
            )

    def test_filename_is_safely_generated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = PDFReportGenerator(
                output_directory=temp_dir
            )

            assessment_data = (
                self.assessment.to_dict()
            )

            assessment_data[
                "assessment_id"
            ] = "ASM/TEST\\REPORT:001"

            path = generator.generate(
                assessment_data
            )

            self.assertTrue(path.exists())
            self.assertNotIn(
                "/",
                path.name,
            )
            self.assertNotIn(
                "\\",
                path.name,
            )

    def test_reportlab_is_available(self):
        self.assertGreater(
            stringWidth(
                "NETWATCH",
                "Helvetica",
                10,
            ),
            0,
        )


if __name__ == "__main__":
    unittest.main()
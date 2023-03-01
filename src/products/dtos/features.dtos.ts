import { IsString, IsUrl, IsNotEmpty, IsArray } from 'class-validator';
import { PartialType, ApiProperty } from '@nestjs/swagger';

export class CreateFeatureDto {
  @IsArray()
  @IsNotEmpty()
  @ApiProperty()
  readonly capacity: string[];

  @IsArray()
  @IsNotEmpty()
  @ApiProperty()
  readonly color: string[];
}

export class UpdateFeatureDto extends PartialType(CreateFeatureDto) {}

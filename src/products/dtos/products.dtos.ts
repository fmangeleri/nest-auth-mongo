import {
  IsString,
  IsNumber,
  IsUrl,
  IsNotEmpty,
  IsPositive,
  IsOptional,
  Min,
  ValidateIf,
  isPositive,
  ValidateNested,
} from 'class-validator';
import { CreateCategoryDto } from './category.dtos';
import { PartialType, ApiProperty } from '@nestjs/swagger';

export class CreateProductDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty({ description: `product's name` })
  readonly name: string;

  @IsString()
  @IsOptional()
  @ApiProperty()
  readonly description: string;

  @IsNumber()
  @IsNotEmpty()
  @IsPositive()
  @ApiProperty()
  readonly price: number;

  @IsNumber()
  @IsNotEmpty()
  @ApiProperty()
  readonly stock: number;

  @IsUrl()
  @IsOptional()
  @ApiProperty()
  readonly image: string;

  @IsNotEmpty()
  @ValidateNested()
  @ApiProperty()
  readonly category: CreateCategoryDto;
}

export class UpdateProductDto extends PartialType(CreateProductDto) {}

export class FilterProductsDto {
  @IsOptional()
  @IsNumber()
  @IsPositive()
  limit: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  offset: number;

  @IsOptional()
  @Min(0)
  minPrice: number;

  @ValidateIf((params) => params.minPrice)
  @IsPositive()
  maxPrice: number;
}
